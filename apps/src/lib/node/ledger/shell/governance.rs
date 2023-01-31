use namada::core::ledger::slash_fund::ADDRESS as slash_fund_address;
use namada::core::types::transaction::governance::ProposalType;
use namada::ledger::events::EventType;
use namada::ledger::governance::{
    storage as gov_storage, ADDRESS as gov_address,
};
use namada::ledger::native_vp::governance::utils::{
    compute_tally, get_proposal_votes, ProposalEvent,
};
use namada::ledger::protocol;
use namada::ledger::storage::types::encode;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::proof_of_stake::PosReadOnly;
use namada::types::address::Address;
use namada::types::governance::{Tally, TallyResult};
use namada::types::storage::Epoch;
use namada::types::token;

use super::*;

#[derive(Default)]
pub struct ProposalsResult {
    passed: Vec<u64>,
    rejected: Vec<u64>,
}

pub fn execute_governance_proposals<D, H>(
    shell: &mut Shell<D, H>,
    response: &mut shim::response::FinalizeBlock,
) -> Result<ProposalsResult>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let mut proposals_result = ProposalsResult::default();

    for id in std::mem::take(&mut shell.proposal_data) {
        let proposal_funds_key = gov_storage::get_funds_key(id);
        let proposal_end_epoch_key = gov_storage::get_voting_end_epoch_key(id);
        let proposal_type_key = gov_storage::get_proposal_type_key(id);

        let funds = shell
            .read_storage_key::<token::Amount>(&proposal_funds_key)
            .ok_or_else(|| {
                Error::BadProposal(id, "Invalid proposal funds.".to_string())
            })?;
        let proposal_end_epoch = shell
            .read_storage_key::<Epoch>(&proposal_end_epoch_key)
            .ok_or_else(|| {
                Error::BadProposal(
                    id,
                    "Invalid proposal end_epoch.".to_string(),
                )
            })?;

        let proposal_type = shell
            .read_storage_key::<ProposalType>(&proposal_type_key)
            .ok_or_else(|| {
                Error::BadProposal(id, "Invalid proposal type".to_string())
            })?;

        let votes = get_proposal_votes(&shell.storage, proposal_end_epoch, id)
            .map_err(|msg| Error::BadProposal(id, msg.to_string()))?;
        let total_stake = shell
            .storage
            .total_stake(proposal_end_epoch)
            .map_err(|msg| Error::BadProposal(id, msg.to_string()))?
            .into();
        let tally_result =
            compute_tally(votes, total_stake, &proposal_type).result;

        // Execute proposal if succesful
        let transfer_address = match tally_result {
            TallyResult::Passed(tally) => {
                match tally {
                    Tally::Default => {
                        let proposal_author_key =
                            gov_storage::get_author_key(id);
                        let proposal_author = shell
                            .read_storage_key::<Address>(&proposal_author_key)
                            .ok_or_else(|| {
                                Error::BadProposal(
                                    id,
                                    "Invalid proposal author.".to_string(),
                                )
                            })?;

                        let proposal_code_key =
                            gov_storage::get_proposal_code_key(id);
                        let proposal_code =
                            shell.read_storage_key_bytes(&proposal_code_key);
                        match proposal_code {
                            Some(proposal_code) => {
                                let tx =
                                    Tx::new(proposal_code, Some(encode(&id)));
                                let tx_type =
                                    TxType::Decrypted(DecryptedTx::Decrypted {
                                        tx,
                                        #[cfg(not(feature = "mainnet"))]
                                        has_valid_pow: false,
                                    });
                                let pending_execution_key =
                                    gov_storage::get_proposal_execution_key(id);
                                shell
                                    .storage
                                    .write(&pending_execution_key, "")
                                    .expect(
                                        "Should be able to write to storage.",
                                    );
                                let tx_result = protocol::apply_tx(
                                    tx_type,
                                    0, /*  this is used to compute the fee
                                        * based on the code size. We dont
                                        * need it here. */
                                    TxIndex::default(),
                                    &mut BlockGasMeter::default(),
                                    &mut shell.write_log,
                                    &shell.storage,
                                    &mut shell.vp_wasm_cache,
                                    &mut shell.tx_wasm_cache,
                                );
                                shell
                                    .storage
                                    .delete(&pending_execution_key)
                                    .expect(
                                        "Should be able to delete the storage.",
                                    );
                                match tx_result {
                                    Ok(tx_result) => {
                                        if tx_result.is_accepted() {
                                            shell.write_log.commit_tx();
                                            let proposal_event: Event =
                                                ProposalEvent::new(
                                                    EventType::Proposal
                                                        .to_string(),
                                                    TallyResult::Passed(
                                                        Tally::Default,
                                                    ),
                                                    id,
                                                    true,
                                                    true,
                                                )
                                                .into();
                                            response
                                                .events
                                                .push(proposal_event);
                                            proposals_result.passed.push(id);

                                            proposal_author
                                        } else {
                                            shell.write_log.drop_tx();
                                            let proposal_event: Event =
                                                ProposalEvent::new(
                                                    EventType::Proposal
                                                        .to_string(),
                                                    TallyResult::Passed(
                                                        Tally::Default,
                                                    ),
                                                    id,
                                                    true,
                                                    false,
                                                )
                                                .into();
                                            response
                                                .events
                                                .push(proposal_event);
                                            proposals_result.rejected.push(id);

                                            slash_fund_address
                                        }
                                    }
                                    Err(_e) => {
                                        shell.write_log.drop_tx();
                                        let proposal_event: Event =
                                            ProposalEvent::new(
                                                EventType::Proposal.to_string(),
                                                TallyResult::Passed(
                                                    Tally::Default,
                                                ),
                                                id,
                                                true,
                                                false,
                                            )
                                            .into();
                                        response.events.push(proposal_event);
                                        proposals_result.rejected.push(id);

                                        slash_fund_address
                                    }
                                }
                            }
                            None => {
                                let proposal_event: Event = ProposalEvent::new(
                                    EventType::Proposal.to_string(),
                                    TallyResult::Passed(Tally::Default),
                                    id,
                                    false,
                                    false,
                                )
                                .into();
                                response.events.push(proposal_event);
                                proposals_result.passed.push(id);

                                proposal_author
                            }
                        }
                    }
                    Tally::PGFCouncil(council) => {
                        // TODO: implement when PGF is in place, update the PGF
                        // council in storage
                        let proposal_event: Event = ProposalEvent::new(
                            EventType::Proposal.to_string(),
                            TallyResult::Passed(Tally::PGFCouncil(council)),
                            id,
                            false,
                            false,
                        )
                        .into();
                        response.events.push(proposal_event);
                        proposals_result.passed.push(id);

                        let proposal_author_key =
                            gov_storage::get_author_key(id);

                        shell
                            .read_storage_key::<Address>(&proposal_author_key)
                            .ok_or_else(|| {
                                Error::BadProposal(
                                    id,
                                    "Invalid proposal author.".to_string(),
                                )
                            })?
                    }
                    Tally::ETHBridge => {
                        // TODO: implement when ETH Bridge. Apply the
                        // modification requested by the proposal
                        let proposal_event: Event = ProposalEvent::new(
                            EventType::Proposal.to_string(),
                            TallyResult::Passed(Tally::ETHBridge),
                            id,
                            false,
                            false,
                        )
                        .into();
                        response.events.push(proposal_event);
                        proposals_result.passed.push(id);

                        let proposal_author_key =
                            gov_storage::get_author_key(id);

                        shell
                            .read_storage_key::<Address>(&proposal_author_key)
                            .ok_or_else(|| {
                                Error::BadProposal(
                                    id,
                                    "Invalid proposal author.".to_string(),
                                )
                            })?
                    }
                }
            }
            TallyResult::Rejected => {
                let proposal_event: Event = ProposalEvent::new(
                    EventType::Proposal.to_string(),
                    TallyResult::Rejected,
                    id,
                    false,
                    false,
                )
                .into();
                response.events.push(proposal_event);
                proposals_result.rejected.push(id);

                slash_fund_address
            }
            TallyResult::Failed(msg) => {
                tracing::error!(
                    "Unexpectedly failed to tally proposal ID {id} with error \
                     {msg}"
                );
                let proposal_event: Event = ProposalEvent::new(
                    EventType::Proposal.to_string(),
                    TallyResult::Failed(msg),
                    id,
                    false,
                    false,
                )
                .into();
                response.events.push(proposal_event);

                let proposal_author_key = gov_storage::get_author_key(id);
                shell
                    .read_storage_key::<Address>(&proposal_author_key)
                    .ok_or_else(|| {
                        Error::BadProposal(
                            id,
                            "Invalid proposal author.".to_string(),
                        )
                    })?
            }
        };

        let native_token = shell.storage.native_token.clone();
        // transfer proposal locked funds
        shell.storage.transfer(
            &native_token,
            funds,
            &gov_address,
            &transfer_address,
        );
    }

    Ok(proposals_result)
}
