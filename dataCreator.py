#!/usr/bin/env python3
import socket
import struct
import nstp_v4_pb2
import nacl
from nacl.public import PublicKey, PrivateKey, Box
import nacl.bindings
import nacl.secret
import sys
import hashlib
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, argon2
import threading
import time
import yaml

def bytesOfFields(msg):
    packed = b''
    for i in msg.subjects:
        packed += i.encode("UTF-8")
    packed += msg.valid_from.to_bytes(8, "big")
    packed += msg.valid_length.to_bytes(4, "big")
    for i in msg.usages:
        packed += i.to_bytes(1, "big")
    packed += msg.encryption_public_key
    packed += msg.signing_public_key
    if msg.HasField("issuer"):
        packed += msg.issuer.value
        packed += msg.issuer.algorithm.to_bytes(1, "big")
    return packed

def createSignature(msg, key):
    hashed = nacl.bindings.crypto_sign_ed25519ph_state()
    packed = bytesOfFields(msg)
    nacl.bindings.crypto_sign_ed25519ph_update(hashed, packed)
    value = nacl.bindings.crypto_sign_ed25519ph_final_create(hashed, key)
    print("VALUE :", value )
    return value

def verifySignature(msg, key):
    hashed = nacl.bindings.crypto_sign_ed25519ph_state()
    packed = bytesOfFields(msg)
    nacl.bindings.crypto_sign_ed25519ph_update(hashed, packed)
    value = nacl.bindings.crypto_sign_ed25519ph_final_verify(hashed, msg.issuer_signature, key)
    print("VALUE :", value )
    return value

def hashCert(msg, alg):
    print("IN HASH: ", msg)
    packed = bytesOfFields(msg)
    if msg.issuer_signature != b'':
        packed += msg.issuer_signature
    if alg == 1:
        hashed = hashlib.sha256(packed)
    elif alg == 2:
        hashed = hashlib.sha512(packed)
    return hashed.digest()

def CertStore():
    msg = nstp_v4_pb2.CertificateStore()

    return 0

def Cert(subject, vFrom, vLength, usages, encPK, sigPK, issuer, key):
    msg = nstp_v4_pb2.Certificate()
    msg.subjects.append(subject)
    msg.valid_from = vFrom
    msg.valid_length = vLength
    msg.usages.append(usages)
    msg.encryption_public_key = encPK
    msg.signing_public_key = sigPK
    if issuer != None:
        msg.issuer.CopyFrom(issuer)

    issuerSig = createSignature(msg, key)
    msg.issuer_signature = issuerSig

    print("MSG: ", msg)
    return msg


def main():
    IssuerESecretKey = PrivateKey.generate()
    IssuerEPublicKey = IssuerESecretKey.public_key
    
    IssuerSSecretKey = PrivateKey.generate()
    IssuerSPublicKey = IssuerSSecretKey.public_key

    EncryptionSecretKey = PrivateKey.generate()
    EncryptionPublicKey = EncryptionSecretKey.public_key

    SigningSecretKey = PrivateKey.generate()
    SigningPublicKey = SigningSecretKey.public_key


    f = open("data/ca.key", "rb")
    contents = f.read()
    caKey = nstp_v4_pb2.PrivateKey()
    caKey.ParseFromString(contents)
    print("Key: " , caKey)

    print(len(PrivateKey.generate().encode()))
    caCert = Cert("CA", 1582760093, 10000000, 3, bytes(IssuerEPublicKey),bytes(IssuerSPublicKey), None, caKey.signing_private_key)
    caCertHash = nstp_v4_pb2.CertificateHash()
    caCertHash.value = hashCert(caCert, 1)
    caCertHash.algorithm = 1
    
    # Invalid time
    invalidTime = Cert("root", 0, 10, 1, bytes(EncryptionPublicKey), bytes(SigningPublicKey), caCertHash, caKey.signing_private_key)

    f = open("test/badTime.crt", "wb")
    f.write(invalidTime.SerializeToString())
    # TODO serialize to string


main()
