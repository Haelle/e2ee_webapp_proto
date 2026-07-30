"""Modèles d'échange. Les champs binaires sont des chaînes base64 (voir codec)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel


# --- auth ------------------------------------------------------------------ #
class ChallengeReq(BaseModel):
    matricule: str


class ChallengeResp(BaseModel):
    nonce: str  # base64


class VerifyReq(BaseModel):
    matricule: str
    sig: str  # base64, signature Ed25519 du nonce


# --- membres --------------------------------------------------------------- #
class EnrollReq(BaseModel):
    matricule: str
    display_name: str
    age_recipient: str
    ed25519_pub: str  # base64
    wrapped_seed: str  # base64


class EnrollResp(BaseModel):
    member_id: uuid.UUID
    key_id: uuid.UUID


class KeyblobResp(BaseModel):
    wrapped_seed: str  # base64


class RotateReq(BaseModel):
    age_recipient: str
    ed25519_pub: str  # base64
    wrapped_seed: str  # base64


# --- groupes / époques ----------------------------------------------------- #
class GroupCreateReq(BaseModel):
    # id fourni par le client pour que la déclaration `found` puisse le référencer
    id: uuid.UUID
    name: str


class GroupResp(BaseModel):
    id: uuid.UUID
    name: str


class EpochResp(BaseModel):
    n: int
    gk_envelope: str  # base64


class EpochCreateReq(BaseModel):
    n: int
    gk_envelope: str  # base64
    # déclaration associée (SPEC §8 : « enveloppe + déclaration associée »)
    seq: int
    stmt: str  # base64 (octets CBOR exacts, signés)
    sig: str  # base64
    signer_key_id: uuid.UUID


# --- chaîne d'octrois ------------------------------------------------------ #
class GrantReq(BaseModel):
    seq: int
    stmt: str  # base64
    sig: str  # base64
    signer_key_id: uuid.UUID


class GrantResp(BaseModel):
    seq: int
    stmt: str  # base64
    sig: str  # base64
    signer_key_id: uuid.UUID
    signer_ed25519_pub: str  # base64 — résolu par le serveur pour le rejeu client
    signer_matricule: str
    hash: str  # base64


# --- notes ----------------------------------------------------------------- #
class NoteResp(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    epoch_n: int
    author_id: uuid.UUID
    wrapped_cek: str  # base64
    payload: str  # base64
    created_at: str
    updated_at: str


class NoteCreateReq(BaseModel):
    # id généré par le client : le payload est scellé AVANT l'envoi et son AAD
    # lie le chiffré à cet id (SPEC §6). Le serveur ne fait que le stocker.
    id: uuid.UUID
    group_id: uuid.UUID
    epoch_n: int
    wrapped_cek: str  # base64
    payload: str  # base64


class NoteResp201(BaseModel):
    id: uuid.UUID


class NotePatchReq(BaseModel):
    epoch_n: int
    wrapped_cek: str  # base64
    payload: str  # base64
