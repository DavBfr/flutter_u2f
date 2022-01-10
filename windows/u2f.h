#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if _WIN32
#include <windows.h>
#define FFI_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FFI_PLUGIN_EXPORT
#define PCWSTR wchar_t*
#define BOOL int
#define DWORD unsigned long
#define PBYTE uint8_t*
#endif

typedef struct {
  DWORD size;
  PBYTE keyHandle;
} KEY_HANDLE;

typedef struct {
  DWORD cbAttestationObject;
  PBYTE pbAttestationObject;
} REGISTER_ATTESTATION;

typedef struct {
  DWORD keyHandleLength;
  PBYTE keyHandle;
  DWORD authenticatorDataLength;
  PBYTE authenticatorData;
  DWORD signatureLength;
  PBYTE signature;
} VALIDATE_ATTESTATION;

FFI_PLUGIN_EXPORT int RegisterFIDO2Token(DWORD clientDataLength,
                                         PBYTE clientData,
                                         PCWSTR appId,
                                         PCWSTR name,
                                         PCWSTR displayName,
                                         DWORD keyHandlesCount,
                                         KEY_HANDLE* keyHandles,
                                         DWORD timeout,
                                         REGISTER_ATTESTATION* attestation);

FFI_PLUGIN_EXPORT int ValidateFIDO2Tokens(DWORD clientDataLength,
                                          PBYTE clientData,
                                          PCWSTR appId,
                                          DWORD keyHandlesCount,
                                          KEY_HANDLE* keyHandles,
                                          DWORD timeout,
                                          VALIDATE_ATTESTATION* validate);

FFI_PLUGIN_EXPORT int FreeRegister(REGISTER_ATTESTATION* attestation);
FFI_PLUGIN_EXPORT int FreeValidate(VALIDATE_ATTESTATION* validate);
