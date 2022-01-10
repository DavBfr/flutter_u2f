#include "u2f.h"

#include <webauthn.h>

int ValidateFIDO2Tokens(DWORD clientDataLength,
                        PBYTE clientData,
                        PCWSTR appId,
                        DWORD keyHandlesCount,
                        KEY_HANDLE* keyHandles,
                        DWORD timeout,
                        VALIDATE_ATTESTATION* validate) {
  WEBAUTHN_CLIENT_DATA webAuthNClientData = {
      WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,  // Structure version
      clientDataLength,
      clientData,
      WEBAUTHN_HASH_ALGORITHM_SHA_256,
  };

  PWEBAUTHN_CREDENTIAL credentials = (PWEBAUTHN_CREDENTIAL)malloc(
      sizeof(WEBAUTHN_CREDENTIAL) * keyHandlesCount);

  for (DWORD i = 0; i < keyHandlesCount; i++) {
    credentials[i].dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    credentials[i].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    credentials[i].cbId = keyHandles[i].size;
    credentials[i].pbId = keyHandles[i].keyHandle;
  }

  WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS webAuthNAssertionOptions = {
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
      timeout,
      {keyHandlesCount, credentials},  // CredentialList
      {0, NULL},                       // Extensions
      WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2,
      WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
      0,  // dwFlags
      NULL,
      NULL,
      NULL,  // pCancellationId
      NULL,
  };

  PWEBAUTHN_ASSERTION pWebAuthNAssertion = NULL;
  HRESULT hr = WebAuthNAuthenticatorGetAssertion(
      GetForegroundWindow(), appId, &webAuthNClientData,
      &webAuthNAssertionOptions, &pWebAuthNAssertion);
  if (SUCCEEDED(hr) && NULL != pWebAuthNAssertion) {
    validate->authenticatorDataLength = pWebAuthNAssertion->cbAuthenticatorData;
    validate->authenticatorData =
        (PBYTE)malloc(validate->authenticatorDataLength);
    memcpy(validate->authenticatorData, pWebAuthNAssertion->pbAuthenticatorData,
           validate->authenticatorDataLength);

    validate->signatureLength = pWebAuthNAssertion->cbSignature;
    validate->signature = (PBYTE)malloc(validate->signatureLength);
    memcpy(validate->signature, pWebAuthNAssertion->pbSignature,
           validate->signatureLength);

    validate->keyHandleLength = pWebAuthNAssertion->cbUserId;
    validate->keyHandle = (PBYTE)malloc(validate->keyHandleLength);
    memcpy(validate->keyHandle, pWebAuthNAssertion->pbUserId,
           validate->keyHandleLength);

    WebAuthNFreeAssertion(pWebAuthNAssertion);
    free(credentials);
    return 0;
  }
  return 1;
}

int FreeValidate(VALIDATE_ATTESTATION* validate) {
  free(validate->authenticatorData);
  free(validate->keyHandle);
  free(validate->signature);
}
