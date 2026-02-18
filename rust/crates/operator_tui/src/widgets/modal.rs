#![allow(dead_code)]

pub(crate) enum ModalKind {
    Placeholder,
}

pub(crate) struct ModalState {
    pub(crate) kind: ModalKind,
}
