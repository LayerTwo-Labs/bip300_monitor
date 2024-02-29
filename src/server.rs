use std::io::Cursor;

use bitcoin::absolute::Height;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::opcodes::all::OP_PUSHBYTES_1;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Block, OutPoint, Transaction, TxOut};
use miette::{miette, IntoDiagnostic, Result};
use tonic::{Request, Response, Status};

use bip300::validator_server::Validator;
use bip300::{ConnectBlockRequest, ConnectBlockResponse};
use bip300::{DisconnectBlockRequest, DisconnectBlockResponse};
use bip300::{IsValidRequest, IsValidResponse};

use redb::{Database, ReadableTable, TableDefinition};

use self::bip300::{AckBundlesEnum, GetCoinbasePsbtRequest, GetCoinbasePsbtResponse};
use crate::types::*;
use bip300_messages::{
    parse_coinbase_script, sha256d, CoinbaseMessage, M4AckBundles, ABSTAIN_ONE_BYTE,
    ABSTAIN_TWO_BYTES, ALARM_ONE_BYTE, ALARM_TWO_BYTES, OP_DRIVECHAIN,
};

pub mod bip300 {
    tonic::include_proto!("validator");
}

const DATA_HASH_TO_SIDECHAIN_PROPOSAL: TableDefinition<&Hash256, SidechainProposal> =
    TableDefinition::new("data_hash_to_sidechain_proposal");

const SIDECHAIN_NUMBER_TO_BUNDLES: TableDefinition<u8, Vec<Bundle>> =
    TableDefinition::new("sidechain_number_to_bundles");

const SIDECHAIN_NUMBER_TO_SIDECHAIN: TableDefinition<u8, Sidechain> =
    TableDefinition::new("sidechain_number_to_sidechain");

const PREVIOUS_VOTES: TableDefinition<(), Vec<&Hash256>> =
    TableDefinition::new("previous_vote_vector");

const LEADING_BY_50: TableDefinition<(), Vec<&Hash256>> = TableDefinition::new("leading_by_50");

const SIDECHAIN_NUMBER_TO_CTIP: TableDefinition<u8, Ctip> =
    TableDefinition::new("sidechain_number_to_ctip");

pub struct Bip300 {
    db: Database,
}

impl Bip300 {
    pub fn new() -> Result<Self> {
        let path = "./bip300.redb";
        let db = Database::create(path).into_diagnostic()?;
        Ok(Self { db })
    }

    pub fn connect_block(&self, block: &Block, height: u32) -> Result<()> {
        println!("connect block");
        // TODO: Check that there are no duplicate M2s.
        let coinbase = &block.txdata[0];

        let write_txn = self.db.begin_write().into_diagnostic()?;
        for output in &coinbase.output {
            match &parse_coinbase_script(&output.script_pubkey) {
                Ok((_, message)) => {
                    match message {
                        CoinbaseMessage::M1ProposeSidechain {
                            sidechain_number,
                            data,
                        } => {
                            let mut data_hash_to_sidechain_proposal = write_txn
                                .open_table(DATA_HASH_TO_SIDECHAIN_PROPOSAL)
                                .into_diagnostic()?;
                            let data_hash: Hash256 = sha256d(&data);
                            if data_hash_to_sidechain_proposal
                                .get(&data_hash)
                                .into_diagnostic()?
                                .is_some()
                            {
                                continue;
                            }
                            let sidechain_proposal = SidechainProposal {
                                sidechain_number: *sidechain_number,
                                data: data.clone(),
                                vote_count: 0,
                                proposal_height: height,
                            };
                            data_hash_to_sidechain_proposal
                                .insert(&data_hash, sidechain_proposal)
                                .into_diagnostic()?;
                        }
                        CoinbaseMessage::M2AckSidechain {
                            sidechain_number,
                            data_hash,
                        } => {
                            let mut data_hash_to_sidechain_proposal = write_txn
                                .open_table(DATA_HASH_TO_SIDECHAIN_PROPOSAL)
                                .into_diagnostic()?;
                            let sidechain_proposal = data_hash_to_sidechain_proposal
                                .get(data_hash)
                                .into_diagnostic()?
                                .map(|s| s.value());
                            if let Some(mut sidechain_proposal) = sidechain_proposal {
                                // Does it make sense to check for sidechain number?
                                if sidechain_proposal.sidechain_number == *sidechain_number {
                                    sidechain_proposal.vote_count += 1;

                                    data_hash_to_sidechain_proposal
                                        .insert(data_hash, &sidechain_proposal)
                                        .into_diagnostic()?;

                                    const USED_MAX_AGE: u16 = 26_300;
                                    const USED_THRESHOLD: u16 = 13_150;

                                    const UNUSED_MAX_AGE: u16 = 2016;
                                    const UNUSED_THRESHOLD: u16 = UNUSED_MAX_AGE - 201;

                                    let sidechain_proposal_age =
                                        height - sidechain_proposal.proposal_height;

                                    let mut sidechain_number_to_sidechain = write_txn
                                        .open_table(SIDECHAIN_NUMBER_TO_SIDECHAIN)
                                        .into_diagnostic()?;

                                    let used = sidechain_number_to_sidechain
                                        .get(sidechain_proposal.sidechain_number)
                                        .into_diagnostic()?
                                        .is_some();

                                    let failed = used
                                        && sidechain_proposal_age > USED_MAX_AGE as u32
                                        && sidechain_proposal.vote_count <= USED_THRESHOLD
                                        || !used
                                            && sidechain_proposal_age > UNUSED_MAX_AGE as u32
                                            && sidechain_proposal.vote_count <= UNUSED_THRESHOLD;

                                    let succeeded = used
                                        && sidechain_proposal.vote_count > USED_THRESHOLD
                                        || !used
                                            && sidechain_proposal.vote_count > UNUSED_THRESHOLD;

                                    if failed {
                                        data_hash_to_sidechain_proposal
                                            .remove(data_hash)
                                            .into_diagnostic()?;
                                    } else if succeeded {
                                        if sidechain_proposal.vote_count > USED_THRESHOLD {
                                            let sidechain = Sidechain {
                                                sidechain_number: sidechain_proposal
                                                    .sidechain_number,
                                                data: sidechain_proposal.data,
                                                proposal_height: sidechain_proposal.proposal_height,
                                                activation_height: height,
                                                vote_count: sidechain_proposal.vote_count,
                                            };
                                            sidechain_number_to_sidechain
                                                .insert(sidechain.sidechain_number, sidechain)
                                                .into_diagnostic()?;
                                            data_hash_to_sidechain_proposal
                                                .remove(data_hash)
                                                .into_diagnostic()?;
                                        }
                                    };
                                }
                            }
                        }
                        CoinbaseMessage::M3ProposeBundle {
                            sidechain_number,
                            bundle_txid,
                        } => {
                            let mut table = write_txn
                                .open_table(SIDECHAIN_NUMBER_TO_BUNDLES)
                                .into_diagnostic()?;
                            let bundles = table
                                .get(sidechain_number)
                                .into_diagnostic()?
                                .map(|bundles| bundles.value());
                            if let Some(mut bundles) = bundles {
                                let bundle = Bundle {
                                    bundle_txid: *bundle_txid,
                                    vote_count: 0,
                                };
                                bundles.push(bundle);
                                table.insert(sidechain_number, bundles).into_diagnostic()?;
                            }
                        }
                        CoinbaseMessage::M4AckBundles(m4) => match m4 {
                            M4AckBundles::LeadingBy50 => {
                                todo!();
                            }
                            M4AckBundles::RepeatPrevious => {
                                todo!();
                            }
                            M4AckBundles::OneByte { upvotes } => {
                                let mut table = write_txn
                                    .open_table(SIDECHAIN_NUMBER_TO_BUNDLES)
                                    .into_diagnostic()?;
                                for (sidechain_number, vote) in upvotes.iter().enumerate() {
                                    if *vote == ABSTAIN_ONE_BYTE {
                                        continue;
                                    }
                                    let bundles = table
                                        .get(sidechain_number as u8)
                                        .into_diagnostic()?
                                        .map(|bundles| bundles.value());
                                    if let Some(mut bundles) = bundles {
                                        if *vote == ALARM_ONE_BYTE {
                                            for bundle in &mut bundles {
                                                if bundle.vote_count > 0 {
                                                    bundle.vote_count -= 1;
                                                }
                                            }
                                        } else if let Some(bundle) = bundles.get_mut(*vote as usize)
                                        {
                                            bundle.vote_count += 1;
                                        }
                                        table
                                            .insert(sidechain_number as u8, bundles)
                                            .into_diagnostic()?;
                                    }
                                }
                            }
                            M4AckBundles::TwoBytes { upvotes } => {
                                let mut table = write_txn
                                    .open_table(SIDECHAIN_NUMBER_TO_BUNDLES)
                                    .into_diagnostic()?;
                                for (sidechain_number, vote) in upvotes.iter().enumerate() {
                                    if *vote == ABSTAIN_TWO_BYTES {
                                        continue;
                                    }
                                    let bundles = table
                                        .get(sidechain_number as u8)
                                        .into_diagnostic()?
                                        .map(|bundles| bundles.value());
                                    if let Some(mut bundles) = bundles {
                                        if *vote == ALARM_TWO_BYTES {
                                            for bundle in &mut bundles {
                                                if bundle.vote_count > 0 {
                                                    bundle.vote_count -= 1;
                                                }
                                            }
                                        } else if let Some(bundle) = bundles.get_mut(*vote as usize)
                                        {
                                            bundle.vote_count += 1;
                                        }
                                        table
                                            .insert(sidechain_number as u8, bundles)
                                            .into_diagnostic()?;
                                    }
                                }
                            }
                        },
                    }
                }
                Err(err) => {
                    return Err(miette!("failed to parse coinbase script: {err}"));
                }
            }
        }

        for transaction in &block.txdata[1..] {
            // TODO: Check that there is only onen OP_DRIVECHAIN.
            let mut new_ctip = None;
            let mut sidechain_number = None;
            let mut new_total_value = None;
            for (vout, output) in transaction.output.iter().enumerate() {
                let script = output.script_pubkey.to_bytes();
                if script[0] == OP_DRIVECHAIN.to_u8() {
                    if new_ctip.is_some() {
                        return Err(miette!("more than one OP_DRIVECHAIN output"));
                    }
                    if script[1] != OP_PUSHBYTES_1.to_u8() {
                        return Err(miette!("invalid OP_DRIVECHAIN output"));
                    }
                    if script[3] != OP_TRUE.to_u8() {
                        return Err(miette!("invalid OP_DRIVECHAIN output"));
                    }
                    sidechain_number = Some(script[2]);
                    new_ctip = Some(OutPoint {
                        txid: transaction.txid(),
                        vout: vout as u32,
                    });
                    new_total_value = Some(output.value.to_sat());
                }
            }
            if let (Some(new_ctip), Some(sidechain_number), Some(new_total_value)) =
                (new_ctip, sidechain_number, new_total_value)
            {
                let mut sidechain_number_to_ctip = write_txn
                    .open_table(SIDECHAIN_NUMBER_TO_CTIP)
                    .into_diagnostic()?;
                let mut old_ctip_found = false;
                let old_total_value = {
                    let old_ctip = sidechain_number_to_ctip
                        .get(sidechain_number)
                        .into_diagnostic()?;
                    if let Some(old_ctip) = old_ctip {
                        for input in &transaction.input {
                            if input.previous_output == old_ctip.value().outpoint {
                                old_ctip_found = true;
                            }
                        }
                        old_ctip.value().value
                    } else {
                        return Err(miette!("sidechain {sidechain_number} doesn't have ctip"));
                    }
                };
                if old_ctip_found {
                    if new_total_value >= old_total_value {
                        // M5
                        // deposit
                        // What would happen if new CTIP value is equal to old CTIP value?
                        // for now it is treated as a deposit of 0.
                        let new_ctip = Ctip {
                            outpoint: new_ctip,
                            value: new_total_value,
                        };
                        sidechain_number_to_ctip
                            .insert(sidechain_number, new_ctip)
                            .into_diagnostic()?;
                    } else {
                        // M6
                        // set correspondidng withdrawal bundle hash as spent
                        todo!();
                    }
                } else {
                    return Err(miette!(
                        "old ctip wasn't spent for sidechain {sidechain_number}"
                    ));
                }
            }
            dbg!(transaction);
        }

        write_txn.commit().into_diagnostic()?;

        {
            let read_txn = self.db.begin_read().into_diagnostic()?;
            let table = read_txn
                .open_table(DATA_HASH_TO_SIDECHAIN_PROPOSAL)
                .into_diagnostic()?;
            for item in table.iter().into_diagnostic()? {
                let (key, value) = item.into_diagnostic()?;
                dbg!(value.value());
            }
        }
        Ok(())
    }

    pub fn disconnect_block(&self, block: &Block) -> Result<()> {
        todo!();
    }

    pub fn is_block_valid(&self, block: &Block) -> Result<()> {
        // validate a block
        todo!();
    }

    pub fn is_transaction_valid(&self, transaction: &Transaction) -> Result<()> {
        todo!();
    }
}

#[tonic::async_trait]
impl Validator for Bip300 {
    async fn is_valid(
        &self,
        request: Request<IsValidRequest>,
    ) -> Result<Response<IsValidResponse>, Status> {
        //println!("REQUEST = {:?}", request);
        let response = IsValidResponse { valid: true };
        Ok(Response::new(response))
    }

    async fn connect_block(
        &self,
        request: Request<ConnectBlockRequest>,
    ) -> Result<Response<ConnectBlockResponse>, Status> {
        // println!("REQUEST = {:?}", request);
        let request = request.into_inner();
        let mut cursor = Cursor::new(request.block);
        let block = Block::consensus_decode(&mut cursor).unwrap();
        self.connect_block(&block, request.height).unwrap();
        let response = ConnectBlockResponse {};
        Ok(Response::new(response))
    }

    async fn disconnect_block(
        &self,
        request: Request<DisconnectBlockRequest>,
    ) -> Result<Response<DisconnectBlockResponse>, Status> {
        //println!("REQUEST = {:?}", request);
        let response = DisconnectBlockResponse {};
        Ok(Response::new(response))
    }

    async fn get_coinbase_psbt(
        &self,
        request: Request<GetCoinbasePsbtRequest>,
    ) -> Result<Response<GetCoinbasePsbtResponse>, Status> {
        let request = request.into_inner();
        let mut messages = vec![];
        for propose_sidechain in &request.propose_sidechains {
            let sidechain_number = propose_sidechain.sidechain_number as u8;
            let data = propose_sidechain.data.clone();
            let message = CoinbaseMessage::M1ProposeSidechain {
                sidechain_number,
                data,
            };
            messages.push(message);
        }
        for ack_sidechain in &request.ack_sidechains {
            let sidechain_number = ack_sidechain.sidechain_number as u8;
            let data_hash: &[u8; 32] = ack_sidechain.data_hash.as_slice().try_into().unwrap();
            let message = CoinbaseMessage::M2AckSidechain {
                sidechain_number,
                data_hash: data_hash.clone(),
            };
            messages.push(message);
        }
        for propose_bundle in &request.propose_bundles {
            let sidechain_number = propose_bundle.sidechain_number as u8;
            let bundle_txid: &[u8; 32] = &propose_bundle.bundle_txid.as_slice().try_into().unwrap();
            let message = CoinbaseMessage::M3ProposeBundle {
                sidechain_number,
                bundle_txid: bundle_txid.clone(),
            };
            messages.push(message);
        }
        if let Some(ack_bundles) = &request.ack_bundles {
            let message = match ack_bundles.tag() {
                AckBundlesEnum::RepeatPrevious => M4AckBundles::RepeatPrevious,
                AckBundlesEnum::LeadingBy50 => M4AckBundles::LeadingBy50,
                AckBundlesEnum::Upvotes => {
                    let mut two_bytes = false;
                    for upvote in &ack_bundles.upvotes {
                        if *upvote > u8::MAX as u32 {
                            two_bytes = true;
                        }
                        if *upvote > u16::MAX as u32 {
                            panic!("upvote too large");
                        }
                    }
                    if two_bytes {
                        let upvotes = ack_bundles
                            .upvotes
                            .iter()
                            .map(|upvote| upvote.clone().try_into().unwrap())
                            .collect();
                        M4AckBundles::TwoBytes { upvotes }
                    } else {
                        let upvotes = ack_bundles
                            .upvotes
                            .iter()
                            .map(|upvote| upvote.clone().try_into().unwrap())
                            .collect();
                        M4AckBundles::OneByte { upvotes }
                    }
                }
            };
            let message = CoinbaseMessage::M4AckBundles(message);
            messages.push(message);
        }

        let output = messages
            .into_iter()
            .map(|message| TxOut {
                value: Amount::from_sat(0),
                script_pubkey: message.into(),
            })
            .collect();
        let transasction = Transaction {
            output,
            input: vec![],
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            version: Version::TWO,
        };
        let mut psbt = vec![];
        transasction.consensus_encode(&mut psbt).unwrap();

        let response = GetCoinbasePsbtResponse { psbt };
        Ok(Response::new(response))
    }
}

// What should happen if new CTIP value is equal to old CTIP value?
// How is the deposit address encoded?
