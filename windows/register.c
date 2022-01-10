#include "u2f.h"

#include <webauthn.h>

int RegisterFIDO2Token(DWORD clientDataLength,
                       PBYTE clientData,
                       PCWSTR appId,
                       PCWSTR name,
                       PCWSTR displayName,
                       DWORD keyHandlesCount,
                       KEY_HANDLE* keyHandles,
                       DWORD timeout,
                       REGISTER_ATTESTATION* attestation) {
  WEBAUTHN_RP_ENTITY_INFORMATION rPInformation = {
      WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,  // Structure version
      appId,
      L"U2F",
      NULL,
  };

  WEBAUTHN_USER_ENTITY_INFORMATION userInformation = {
      WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,  // Structure version
      (DWORD)wcslen(name),
      (PBYTE)name,
      name,
      NULL,
      displayName,
  };

  WEBAUTHN_CLIENT_DATA webAuthNClientData = {
      WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,  // Structure version
      clientDataLength,
      clientData,
      WEBAUTHN_HASH_ALGORITHM_SHA_256,
  };

  WEBAUTHN_COSE_CREDENTIAL_PARAMETER coseParam = {
      WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,  // Structure version
      WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,  // "public-key" string constant
      WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
  };

  WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyCredParams = {
      1,
      &coseParam,
  };

  WEBAUTHN_CREDENTIAL_EX excludedCred = {
      WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
      0,
      NULL,
      WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
      WEBAUTHN_CTAP_TRANSPORT_USB || WEBAUTHN_CTAP_TRANSPORT_NFC ||
          WEBAUTHN_CTAP_TRANSPORT_BLE,
  };

  WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS webAuthNMakeCredentialOptions =
      {
          WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
          timeout,
          {0, NULL},  // excludedCred
          {0, NULL},  // Extensions
          WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2,
          FALSE,
          WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
          WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
          0,     // Flags
          NULL,  // CancellationId
          NULL,
      };

  WEBAUTHN_CREDENTIAL_ATTESTATION* pWebAuthNCredentialAttestation = NULL;

  HRESULT hr = WebAuthNAuthenticatorMakeCredential(
      GetForegroundWindow(), &rPInformation, &userInformation,
      &pubKeyCredParams, &webAuthNClientData, &webAuthNMakeCredentialOptions,
      &pWebAuthNCredentialAttestation);

  if (SUCCEEDED(hr) && NULL != pWebAuthNCredentialAttestation) {
    attestation->cbAttestationObject =
        pWebAuthNCredentialAttestation->cbAttestationObject;
    attestation->pbAttestationObject =
        (PBYTE)malloc(attestation->cbAttestationObject);
    memcpy(attestation->pbAttestationObject,
           pWebAuthNCredentialAttestation->pbAttestationObject,
           attestation->cbAttestationObject);

    WebAuthNFreeCredentialAttestation(pWebAuthNCredentialAttestation);
    return 0;
  } else {
    wprintf(L"Error %s", WebAuthNGetErrorName(hr));
    return 1;
  }
}

int FreeRegister(REGISTER_ATTESTATION* attestation) {
  free(attestation->pbAttestationObject);
}
