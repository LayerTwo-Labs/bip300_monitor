use std::io::Cursor;
use std::mem::size_of;

use bitcoin::absolute::Height;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::transaction::Version;
// 0b65bc611f8cb22f782d59a71a4eb68dacc348bccbfa04e0bfc83589c94ed656
use bitcoin::{Amount, Block, Transaction, TxOut};
use miette::{miette, IntoDiagnostic, Result};
use tonic::{Request, Response, Status};

use byteorder::{BigEndian, ByteOrder};

use bip300::validator_server::Validator;
use bip300::{ConnectBlockRequest, ConnectBlockResponse};
use bip300::{DisconnectBlockRequest, DisconnectBlockResponse};
use bip300::{IsValidRequest, IsValidResponse};

use redb::{Database, ReadableTable, RedbValue, TableDefinition, TypeName};

use serde::{Deserialize, Serialize};

use self::bip300::{AckBundlesEnum, GetCoinbasePsbtRequest, GetCoinbasePsbtResponse};
use bip300_messages::{
    parse_coinbase_script, sha256d, CoinbaseMessage, M4AckBundles, ABSTAIN_ONE_BYTE,
    ABSTAIN_TWO_BYTES, ALARM_ONE_BYTE, ALARM_TWO_BYTES,
};

use sha2::{Digest, Sha256};

type Hash256 = [u8; 32];

pub mod bip300 {
    tonic::include_proto!("validator");
}

// data_hash -> { sidechain_number, data, vote_count }
// bundle_txid -> { sidechain_number, bundle, vote_count }
// (sidechain_number, deposit_number) -> { address, value }

// Atomic Swap support
// Standard deposits
// Standard withdrawals
// Standard BIP300

const DATA_HASH_TO_SIDECHAIN_PROPOSAL: TableDefinition<&Hash256, SidechainProposal> =
    TableDefinition::new("data_hash_to_sidechain_proposal");

const SIDECHAIN_NUMBER_TO_BUNDLES: TableDefinition<u8, Vec<Bundle>> =
    TableDefinition::new("sidechain_number_to_bundles");

const SIDECHAIN_NUMBER_TO_SIDECHAIN: TableDefinition<u8, Sidechain> =
    TableDefinition::new("sidechain_number_to_sidechain");

const PREVIOUS_VOTES: TableDefinition<(), Vec<&Hash256>> =
    TableDefinition::new("previous_vote_vector");

const LEADING_BY_50: TableDefinition<(), Vec<&Hash256>> = TableDefinition::new("leading_by_50");

// Generate these table definitions dynamically.
const DEPOSIT_TXOS_0: TableDefinition<u64, Deposit> = TableDefinition::new("deposit_txos_0");
const DEPOSIT_TXOS_1: TableDefinition<u64, Deposit> = TableDefinition::new("deposit_txos_1");
const DEPOSIT_TXOS_2: TableDefinition<u64, Deposit> = TableDefinition::new("deposit_txos_2");
const DEPOSIT_TXOS_3: TableDefinition<u64, Deposit> = TableDefinition::new("deposit_txos_3");
const DEPOSIT_TXOS_4: TableDefinition<u64, Deposit> = TableDefinition::new("deposit_txos_4");

/*
data_hash_to_sidechain_proposal: Database<OwnedType<Hash256>, SerdeBincode<SidechainProposal>>,
bundle_txid_to_bundle: Database<OwnedType<Hash256>, SerdeBincode<Bundle>>,

// big endian number
// 0th byte - 8 bit sidechain number
// 1..9 bytes - 64 bit deposit number
deposit_txos: Database<OwnedType<[u8; 9]>, SerdeBincode<Deposit>>,
*/

pub struct Bip300 {
    db: Database,
}

#[derive(Debug, Serialize, Deserialize)]
struct Deposit {
    address: Hash256,
    value: u64,
}

impl RedbValue for Deposit {
    type SelfType<'a> = Deposit;
    type AsBytes<'a> = [u8; size_of::<Hash256>() + size_of::<u64>()];

    fn type_name() -> TypeName {
        TypeName::new("Deposit")
    }

    fn fixed_width() -> Option<usize> {
        Some(size_of::<Hash256>() + size_of::<u64>())
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let address: Hash256 = data[0..size_of::<Hash256>()].try_into().unwrap();
        let data = &data[size_of::<Hash256>()..];
        let value = BigEndian::read_u64(data);
        Deposit { address, value }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut data = [0; size_of::<Hash256>() + size_of::<u64>()];
        data[0..size_of::<Hash256>()].copy_from_slice(&value.address);
        BigEndian::write_u64(
            &mut data[size_of::<Hash256>()..size_of::<Hash256>() + size_of::<u64>()],
            value.value,
        );
        data
    }
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
        todo!();
    }

    pub fn is_transaction_valid(&self, transaction: &Transaction) -> Result<()> {
        todo!();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Sidechain {
    sidechain_number: u8,
    data: Vec<u8>,
    vote_count: u16,
    proposal_height: u32,
    activation_height: u32,
}

impl RedbValue for Sidechain {
    type SelfType<'a> = Sidechain;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        bincode::deserialize(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        bincode::serialize(value).unwrap()
    }

    fn type_name() -> redb::TypeName {
        TypeName::new("Sidechain")
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SidechainProposal {
    sidechain_number: u8,
    data: Vec<u8>,
    vote_count: u16,
    proposal_height: u32,
}

impl RedbValue for SidechainProposal {
    type SelfType<'a> = SidechainProposal;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        bincode::deserialize(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        bincode::serialize(value).unwrap()
    }

    fn type_name() -> redb::TypeName {
        TypeName::new("SidechainProposal")
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Bundle {
    bundle_txid: Hash256,
    vote_count: u16,
}

impl RedbValue for Bundle {
    type SelfType<'a> = Bundle;
    type AsBytes<'a> = Vec<u8>;

    fn type_name() -> TypeName {
        TypeName::new("Bundle")
    }

    fn fixed_width() -> Option<usize> {
        None
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        bincode::serialize(value).unwrap()
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        bincode::deserialize(data).unwrap()
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
