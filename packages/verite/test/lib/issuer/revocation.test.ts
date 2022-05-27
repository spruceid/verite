import {
  generateRevocationList,
  isRevoked,
  revokeCredential,
  unrevokeCredential
} from "../../../lib/issuer"
import {
  asyncMap,
  decodeVerifiableCredential,
  encodeVerifiableCredential,
  generateBitstring,
  buildIssuer,
  buildPrivateKeyJwk
} from "../../../lib/utils"

import type {
  CredentialPayload,
  JWK,
  Revocable,
  RevocableCredential
} from "../../../types"

const vectors = [
  {
    credentials: [],
    bitstring: "eJztwTEBAAAAwqD1T20MH6AAAAAAAAAAAAAAAAAAAACAtwFAAAAB"
  },
  {
    credentials: [0],
    bitstring: "eJztwSEBAAAAAiCnO90ZFqABAAAAAAAAAAAAAAAAAAAA3gZB4ACB"
  },
  {
    credentials: [3], // zero index
    bitstring: "eJztwSEBAAAAAiAn+H+tMyxAAwAAAAAAAAAAAAAAAAAAALwNQDwAEQ=="
  },
  {
    skipGenerate: true, // When I generate a bitstring, I get the string found in the first vector. However, both these values decode to the same empty array.
    credentials: [],
    bitstring:
      "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA="
  }
]

const credentialFactory = async (
  index: number,
  privateKey: JWK,
  issuerId: string,
): Promise<RevocableCredential> => {
  const vcPayload: Revocable<CredentialPayload> = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    sub: "did:web:example.com",
    type: ["VerifiableCredential"],
    issuer: issuerId,
    issuanceDate: new Date(),
    credentialSubject: {
      id: "did:web:example.com",
      foo: "bar"
    },
    credentialStatus: {
      id: `http://example.com/revocation#${index}`,
      type: "RevocationList2021Status",
      statusListIndex: index.toString(),
      statusListCredential: "http://example.com/revocation"
    }
  }
  const vcJwt = await encodeVerifiableCredential(vcPayload, privateKey)
  return decodeVerifiableCredential(vcJwt) as Promise<RevocableCredential>
}

const statusListFactory = async (statusList: number[]) => {
  const url = "https://example.com/credentials/status/3" // Need to create a list
  const issuer = "did:key:z6MksGKh23mHZz2FpeND6WxJttd8TWhkTga7mtbM1x1zM65m"
  const privateKeyHex = "1f0465e2546027554c41584ca53971dfc3bf44f9b287cb15b5732ad84adb4e63be5aa9b3df96e696f4eaa500ec0b58bf5dfde59200571b44288cc9981279a238"
  const privateKey = buildPrivateKeyJwk(privateKeyHex)
  const issuanceDate = new Date()

  return generateRevocationList({
    statusList,
    url,
    privateKey,
    issuer,
    issuanceDate
  })
}

describe("Status List 2021", () => {
  it("generateRevocationList", async () => {
    const statusList = [3]
    const url = "https://example.com/credentials/status/3" // Need to create a list
    const issuer = "did:key:z6MksGKh23mHZz2FpeND6WxJttd8TWhkTga7mtbM1x1zM65m"

    const vc = await statusListFactory(statusList)
    expect(vc.id).toBe(`${url}`)
    expect(vc.issuer.id).toBe(issuer)
    expect(vc.credentialSubject.type).toBe("RevocationList2021")
    expect(vc.credentialSubject.encodedList).toBe(
      "eJztwSEBAAAAAiAn+H+tMyxAAwAAAAAAAAAAAAAAAAAAALwNQDwAEQ=="
    )
  })

  describe("#isRevoked", () => {
    it("returns false if the given credential has no credentialStatus", async () => {
      const statusList = [3]
      const url = "https://example.com/credentials/status/3" // Need to create a list
      const issuer = "did:key:z6MksGKh23mHZz2FpeND6WxJttd8TWhkTga7mtbM1x1zM65m"
      const privateKeyHex = "1f0465e2546027554c41584ca53971dfc3bf44f9b287cb15b5732ad84adb4e63be5aa9b3df96e696f4eaa500ec0b58bf5dfde59200571b44288cc9981279a238"
      const privateKey = buildPrivateKeyJwk(privateKeyHex)
      const issuanceDate = new Date()

      const revocationList = await generateRevocationList({
        statusList,
        url,
        issuer,
        privateKey,
        issuanceDate
      })

      const vcPayload: CredentialPayload = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiableCredential"],
        issuer,
        issuanceDate,
        credentialSubject: {
          id: "did:web:example.com",
          foo: "bar"
        }
      }
      const vcJwt = await encodeVerifiableCredential(vcPayload, privateKey)
      const credential = await decodeVerifiableCredential(vcJwt)

      const revoked = await isRevoked(credential, revocationList)
      expect(revoked).toBe(false)
    })

    it("returns false if the given credential has a credentialSubject that is not revoked", async () => {
      const statusList: number[] = []
      const url = "https://example.com/credentials/status/3" // Need to create a list
      const issuer = "did:key:z6MksGKh23mHZz2FpeND6WxJttd8TWhkTga7mtbM1x1zM65m"
      const privateKeyHex = "1f0465e2546027554c41584ca53971dfc3bf44f9b287cb15b5732ad84adb4e63be5aa9b3df96e696f4eaa500ec0b58bf5dfde59200571b44288cc9981279a238"
      const issuanceDate = new Date()
      const privateKey = buildPrivateKeyJwk(privateKeyHex)

      const revocationList = await generateRevocationList({
        statusList,
        url,
        issuer,
        privateKey,
        issuanceDate
      })
      const index = 3

      const vcPayload: Revocable<CredentialPayload> = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiableCredential"],
        issuer,
        issuanceDate,
        credentialSubject: {
          id: "did:web:example.com",
          foo: "bar"
        },
        credentialStatus: {
          id: `${url}#${index}`,
          type: "RevocationList2021Status",
          statusListIndex: index.toString(),
          statusListCredential: url
        }
      }
      const vcJwt = await encodeVerifiableCredential(vcPayload, privateKey)
      const credential = await decodeVerifiableCredential(vcJwt)

      const revoked = await isRevoked(credential, revocationList)
      expect(revoked).toBe(false)
    })

    it("returns true if the given credential has a revoked", async () => {
      const statusList = [3]
      const url = "https://example.com/credentials/status/3" // Need to create a list
      const issuer = "did:key:z6MksGKh23mHZz2FpeND6WxJttd8TWhkTga7mtbM1x1zM65m"
      const privateKeyHex = "1f0465e2546027554c41584ca53971dfc3bf44f9b287cb15b5732ad84adb4e63be5aa9b3df96e696f4eaa500ec0b58bf5dfde59200571b44288cc9981279a238"
      const privateKey = buildPrivateKeyJwk(privateKeyHex)
      const issuanceDate = new Date()

      const revocationList = await generateRevocationList({
        statusList,
        url,
        issuer,
        privateKey,
        issuanceDate
      })
      const index = 3

      const vcPayload: Revocable<CredentialPayload> = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiableCredential"],
        issuer,
        issuanceDate,
        credentialSubject: {
          id: "did:web:example.com",
          foo: "bar"
        },
        credentialStatus: {
          id: `${url}#${index}`,
          type: "RevocationList2021Status",
          statusListIndex: index.toString(),
          statusListCredential: url
        }
      }
      const vcJwt = await encodeVerifiableCredential(vcPayload, privateKey)
      const credential = await decodeVerifiableCredential(vcJwt)

      const revoked = await isRevoked(credential, revocationList)
      expect(revoked).toBe(true)
    })
  })

  describe("revokeCredential", () => {
    it("updates the status list credential", async () => {
      const privateKeyHex = "1f0465e2546027554c41584ca53971dfc3bf44f9b287cb15b5732ad84adb4e63be5aa9b3df96e696f4eaa500ec0b58bf5dfde59200571b44288cc9981279a238"
      const issuerId = "did:key:z6MksGKh23mHZz2FpeND6WxJttd8TWhkTga7mtbM1x1zM65m"
      const privateKey = buildPrivateKeyJwk(privateKeyHex)

      const credential = await credentialFactory(3, privateKey, issuerId)
      let statusList = await statusListFactory([])
      expect(await isRevoked(credential, statusList)).toBe(false)

      statusList = await revokeCredential(credential, statusList, privateKey, issuerId)
      expect(await isRevoked(credential, statusList)).toBe(true)

      statusList = await unrevokeCredential(credential, statusList, privateKey, issuerId)
      expect(await isRevoked(credential, statusList)).toBe(false)
    })
  })

  it("generateBitstring", async () => {
    await asyncMap(vectors, async (vector) => {
      const { credentials, bitstring, skipGenerate } = vector

      if (skipGenerate) {
        return
      }

      const encodedList = generateBitstring(credentials)
      expect(encodedList).toEqual(bitstring)
    })
  })
})
