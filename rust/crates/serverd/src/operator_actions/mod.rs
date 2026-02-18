mod approve;
mod capsule_export;
mod common;
mod learnings;
mod refuse;
mod replay_verify;
use crate::command::{
    OperatorApproveArgs, OperatorCapsuleExportArgs, OperatorLearningsAppendArgs,
    OperatorRefuseArgs, OperatorReplayVerifyArgs,
};

pub(crate) fn run_operator_approve(
    args: OperatorApproveArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    approve::run_operator_approve(args)
}

pub(crate) fn run_operator_learnings_append(
    args: OperatorLearningsAppendArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    learnings::run_operator_learnings_append(args)
}
pub(crate) fn run_operator_refuse(
    args: OperatorRefuseArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    refuse::run_operator_refuse(args)
}

pub(crate) fn run_operator_replay_verify(
    args: OperatorReplayVerifyArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    replay_verify::run_operator_replay_verify(args)
}

pub(crate) fn run_operator_capsule_export(
    args: OperatorCapsuleExportArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    capsule_export::run_operator_capsule_export(args)
}
