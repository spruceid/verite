import { buildKycAmlManifest } from "@verity/core"
import type { CredentialManifest } from "@verity/core"
import { fullURL } from "../utils"
import { manifestIssuer } from "./issuer"

export const kycManifest: CredentialManifest = buildKycAmlManifest(
  manifestIssuer,
  {
    thumbnail: {
      uri: fullURL("/img/kyc-aml-thumbnail.png"),
      alt: "Verity Logo"
    },
    hero: {
      uri: fullURL("/img/kyc-aml-hero.png"),
      alt: "KYC+AML Visual"
    },
    background: {
      color: "#EC4899"
    },
    text: {
      color: "#FFFFFF"
    }
  }
)