---
title: "Module 5 — Cloud Security (Quick Reference)"
course: CCDL1
type: quick-reference
tags: [blueteam, cloud, aws, cloudtrail, cloudwatch, incident-response]
---

# Module 5 — Cloud Security

⚠ **Cloud incidents are identity chains, not process chains.** App flaw leaks a credential → used from somewhere unexpected → enumerates → escalates or persists → exfiltrates. Always ask *which identity, and where did it come from?*

---

## Log sources & blind spots

| Source | Records | Blind spot |
|---|---|---|
| **CloudTrail** | Control-plane API calls | ⚠ Data events (S3 objects, Lambda invokes) are **off by default** |
| **CloudWatch Logs** | App output — Lambda, API Gateway, ECS | Only what the app logs |
| **VPC Flow Logs** | Connection metadata | No payload |
| **S3 Server Access Logs** | Bucket-level requests | Best-effort, delayed |
| **GuardDuty** | Analysed findings | Detections, not evidence |
| **Config** | Resource state over time | What changed, not who exploited it |

First question every time: **were data events enabled?** If not, an attacker can read every object in a bucket and only the management-plane calls appear.

---

## AWS identifiers

| Format | Meaning |
|---|---|
| `AKIA...` | Long-term key, IAM **user** |
| `ASIA...` | Temporary STS key — requires session token, came from a role assumption |
| `arn:aws:iam::<ACCT>:role/<Role>` | Role |
| `arn:aws:iam::<ACCT>:user/<User>` | User |
| `arn:aws:sts::<ACCT>:assumed-role/<Role>/<SessionName>` | Assumed session — **`SessionName` is a strong pivot** |
| `/aws/lambda/<Fn>` | CloudWatch log group |
| `https://<API_ID>.execute-api.<Region>.amazonaws.com/<Stage>/<Path>` | API Gateway |

`ASIA` key used from a non-AWS IP shortly after a web exploit = classic stolen credential.

---

## Credential theft from compute — the pivot

**EC2 — IMDS**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
```

Returns `AccessKeyId`, `SecretAccessKey`, `Token`.
- **IMDSv1** — plain GET. Vulnerable to SSRF
- **IMDSv2** — PUT to `/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` first, token on every request

`169.254.169.254` in an application request parameter **is** the finding.

**Lambda — environment variables** (no IMDS):

```
AWS_ACCESS_KEY_ID   AWS_SECRET_ACCESS_KEY   AWS_SESSION_TOKEN
AWS_LAMBDA_FUNCTION_NAME   AWS_REGION
```

Any file-read reaching `/proc/self/environ` steals live credentials.

**XXE via SVG — detection signature:**

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///proc/self/environ" > ]>
```

Alert on `<!DOCTYPE` / `<!ENTITY` inside an uploaded image, `SYSTEM` with `file://` or `http://169.254.169.254`, Base64 in upload params decoding to XML. Check raw **and** decoded.

---

## CloudTrail event fields

```json
"userIdentity": {
  "type": "AssumedRole",
  "arn": "arn:aws:sts::<ACCT>:assumed-role/<Role>/<Session>",
  "accessKeyId": "ASIA...",
  "sessionContext": { "attributes": { "mfaAuthenticated": "false" } }
}
```

`userIdentity.type`: `Root` (investigate every occurrence), `IAMUser`, `AssumedRole`, `FederatedUser`, `AWSService`, `AWSAccount`.

| Field | Why |
|---|---|
| `eventName` | The API call — primary filter |
| `sourceIPAddress` | Origin; service name instead of IP for AWS-internal calls |
| `userAgent` | Tool fingerprint |
| `errorCode` / `errorMessage` | `AccessDenied` bursts = enumeration or failed escalation |
| `requestParameters` | What was asked for |
| `responseElements` | What came back — new key IDs, created usernames |
| `readOnly` | Splits recon from modification |
| `mfaAuthenticated` | `false` on a sensitive action is itself a finding |

⚠ **Listing calls** (`ListBuckets`, `ListSecrets`, `ListUsers`) take no resource argument — result is in **`responseElements`**. **Resource calls** (`GetSecretValue`, `GetBucketAcl`, `PutObject`) name the target in **`requestParameters`**. `requestParameters.bucketName` is empty for `ListBuckets` by design.

---

## API calls by attack phase

**Discovery**

```
GetCallerIdentity                     # "who am I" — very often the first call
ListBuckets, ListObjects
ListUsers, ListRoles, ListPolicies, ListAttachedUserPolicies
GetAccountAuthorizationDetails        # dumps the entire IAM config
DescribeInstances, DescribeSecurityGroups, DescribeSnapshots
ListFunctions, GetFunction            # Lambda env vars returned here
```

**Privilege escalation**

```
AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy
CreatePolicyVersion --set-as-default  # silent escalation, attaches nothing new
UpdateAssumeRolePolicy                # lets attacker's principal assume a privileged role
PassRole (in requestParameters)
```

**Persistence**

```
CreateUser, CreateAccessKey           # second key on an existing user = backdoor
CreateLoginProfile, UpdateLoginProfile
CreateRole, UpdateAssumeRolePolicy
CreateFunction, UpdateFunctionCode
```

**Defence evasion**

```
StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors
DeleteFlowLogs
DeleteDetector, UpdateDetector        # GuardDuty
DeleteLogGroup, DeleteLogStream
```

`StopLogging` has essentially no benign incident-time explanation.

**Collection / exfiltration**

```
GetObject, CopyObject                 # needs S3 data events enabled
PutBucketPolicy, PutBucketAcl, DeletePublicAccessBlock
CreateSnapshot, ModifySnapshotAttribute      # shares EBS snapshot externally
CreateDBSnapshot, ModifyDBSnapshotAttribute
```

`ModifySnapshotAttribute` `requestParameters` contain the **destination account ID** — often the only identifier for attacker infrastructure.

**Session tracking:** `AssumeRole` → `responseElements.credentials.accessKeyId` = the new `ASIA` key. Search on it to follow the session. Repeat for role chaining.

---

## CloudWatch Logs Insights — CloudTrail

⚠ **`@timestamp` ≠ `eventTime`.** `@timestamp` = ingestion; `eventTime` = when the API call happened. The picker and `START=`/`END=` filter ingestion only. After a bulk import every record can share one `@timestamp` while `eventTime` spans days. **Always `sort eventTime asc`.** Error *"end date is either before the log groups creation time"* means exactly this — widen the picker and filter with `| filter eventTime like "2026-01-23"` (ISO 8601 sorts lexicographically).

⚠ **Confirm the source before trusting an empty result.** A CloudTrail query against `/aws/lambda/...` returns zeros for every identity field. Check the **Discovered fields** counter (a handful = unstructured text, ~25 = parsed CloudTrail) and the **Data sources** selector — `aws_cloudtrail.management` for control plane, `aws_cloudtrail.data` for object level.

Reference dotted fields directly; backticks if parsing fails: `` `userIdentity.arn` ``.

**Most identities per IP:**

```
stats count_distinct(userIdentity.arn) as identities,
      count_distinct(userIdentity.accessKeyId) as keys,
      count(*) as calls
      by sourceIPAddress
| sort identities desc
```

**Tool fingerprint:**

```
stats count(*) by sourceIPAddress, userAgent
| sort calls desc
```

**One actor's timeline / follow a stolen session / surface enumeration:**

```
fields @timestamp, eventName, eventSource, userIdentity.arn, errorCode
| filter sourceIPAddress = "<IP>"
| sort eventTime asc

| filter userIdentity.accessKeyId = "<ASIA...>"

| filter ispresent(errorCode)
| stats count(*) as denials by userIdentity.arn, eventName
| sort denials desc
```

---

## Identifying the actor

⚠ **Volume is an exclusion signal, not a suspicion signal.** The noisiest IP is almost always sanctioned automation. Rank by distinct identities. Discard rows whose `sourceIPAddress` is a service name (`lambda.amazonaws.com`, `AWS Internal`, `cloudtrail.amazonaws.com`).

| `userAgent` | Interpretation |
|---|---|
| `Mozilla/5.0 ... Chrome/...` | Console — a human in a browser |
| `Terraform/x.y.z terraform-provider-aws/...` | Infrastructure as code |
| `aws-sdk-go/... amazon-ssm-agent/...` | SSM agent |
| `aws-cli/2.x ... md/command#<service.operation>` | CLI — **the exact command is in the string** |
| `Boto3/x.y.z ... Botocore/x.y.z` | Python script |
| A bare product name | Named tooling — read it literally |

⚠ The `aws-cli` agent embeds the command, so `stats by userAgent` fragments into hundreds of rows. Filter it out for a tool inventory.
⚠ A shared Botocore version across two different agents suggests one host running several tools in one Python environment.
⚠ **When aggregation hides the needle, return to the raw timeline.** A tool making a single API call disappears inside a `stats` result.

**Baseline divergence:** legitimate hosts form a consistent fleet — same CLI and botocore version, same kernel string, a mix of console and CLI because real people use both. An intruder's machine diverges on all counts. `curl` calling the AWS API is close to conclusive: hand-crafted requests, typically testing a stolen key.

**Legitimate admin vs attacker:**

| Signal | Admin | Attacker |
|---|---|---|
| `userAgent` | Console, IaC | Boto3, python-requests, offensive tooling |
| `sourceIPAddress` | Consistent, corporate | External, hosting provider |
| `mfaAuthenticated` | `true` | `false` |
| Timing | Business hours, spread | Compressed into minutes |
| Identity | One stable principal | Several, chained via `AssumeRole` |

⚠ **`AccessDenied` is evidence.** Denial bursts map what was probed. The same call failing then succeeding marks the exact moment of privilege escalation.

**Region distribution:**

```bash
jq -r '.awsRegion' all_events.json | sort | uniq -c | sort -rn
jq -r '[.awsRegion, .eventName] | @tsv' all_events.json | sort | uniq -c | sort -rn | head -40
```

⚠ The same `Describe*`/`List*` set repeating in near-identical proportions across several regions = automated enumeration. A single region whose profile differs (bulk `GetObject` where others show only discovery) = where something happened. Global services (IAM, STS, CloudTrail, CloudFront) log to `us-east-1` regardless.

**Credentials stored in S3** are a recurring entry point:

```bash
jq -r 'select(.requestParameters.key != null) | .requestParameters.key' all_events.json \
  | sort -u | grep -iE "key|cred|secret|config|env|token|\.pem"
```

**First appearance of each identity** — exposes when a new credential entered service:

```bash
jq -r 'select(.sourceIPAddress=="<IP>")
  | [.eventTime, (.userIdentity.userName // .userIdentity.type), .eventName] | @tsv' \
  all_events.json | sort | awk '!seen[$2]++'
```

**Session names as IOCs:**

```
fields eventTime, requestParameters.roleArn, requestParameters.roleSessionName,
       responseElements.assumedRoleUser.arn, responseElements.credentials.accessKeyId,
       sourceIPAddress, errorCode
| filter eventName = "AssumeRole"
| sort eventTime asc
```

`roleSessionName` is attacker-chosen and arbitrary — durable, often reused across intrusions.

---

## Raw CloudTrail on disk

Structure: `AWSLogs/<ACCT>/CloudTrail/<REGION>/<YYYY>/<MM>/<DD>/`. `CloudTrail-Digest/` holds integrity signatures, no events.

```bash
cd AWSLogs/<ACCOUNT_ID>/CloudTrail
for d in */; do echo -n "$d "; find "$d" -name "*.json.gz" | wc -l; done
find . -name "*.json.gz" -exec gunzip -c {} \; | jq -c '.Records[]' > ~/all_events.json
wc -l ~/all_events.json
```

⚠ **`jq` fails silently on a mistyped field** — returns `null`, not an error, so an empty result looks like a finding. Case-sensitive: `awsRegion`, `sourceIPAddress`, `userIdentity`, `requestParameters`, `eventTime`.

```bash
jq -r 'keys[]' all_events.json | sort -u          # the field list
jq -s '.[0]' all_events.json                      # one full event
```

**Write field names once, then filter with `grep`:**

```bash
cat > ~/t.sh << 'EOF'
jq -r '[.eventTime, .awsRegion, .sourceIPAddress, .eventName,
        ((.requestParameters.bucketName // "-") + "/" + (.requestParameters.key // "-")),
        (.errorCode // "-")] | @tsv' ~/all_events.json
EOF
chmod +x ~/t.sh
./t.sh | grep StopLogging
```

**Recipes:**

```bash
jq -r 'select(.sourceIPAddress=="<IP>") | [.eventTime,.eventName,.userIdentity.arn] | @tsv' all_events.json | sort
jq -r 'select(.userIdentity.accessKeyId=="<ASIA...>") | [.eventTime,.eventName,.errorCode] | @tsv' all_events.json | sort
jq -r '.eventName' all_events.json | sort | uniq -c | sort -rn | head -30
jq -r 'select(.errorCode!=null) | [.eventTime,.userIdentity.arn,.eventName,.errorCode] | @tsv' all_events.json | sort
```

**Athena:**

```sql
SELECT eventtime, eventname, useridentity.arn, sourceipaddress, errorcode
FROM cloudtrail_logs WHERE sourceipaddress = '<IP>' ORDER BY eventtime;
```

Partition by region and date or every query scans the bucket.

---

## Secrets Manager / Parameter Store

```
fields eventTime, eventName, userIdentity.arn, requestParameters.secretId, sourceIPAddress, errorCode
| filter eventSource = "secretsmanager.amazonaws.com" or eventSource = "ssm.amazonaws.com"
| sort eventTime asc
```

`ListSecrets` (inventory) → successive `GetSecretValue` (collection) = credential exfiltration → **T1552 Unsecured Credentials**.

⚠ **`PutSecretValue` is not theft, it's sabotage or persistence.** Overwriting a secret consumed by an automated process makes everything downstream silently use attacker-supplied values. Same for `PutParameter` (SSM) and `UpdateFunctionConfiguration` (Lambda).

Every `GetSecretValue` on an encrypted secret produces a matching KMS `Decrypt` — independent corroboration.

---

## IAM persistence & anti-forensics

```bash
jq -r 'select(.eventName | test("^(CreateUser|CreateAccessKey|CreateLoginProfile|AddUserToGroup|AttachUserPolicy|PutUserPolicy)$"))
  | [.eventTime, .eventName, (.requestParameters.userName // "-"),
     (.requestParameters.groupName // .requestParameters.policyArn // "-"),
     (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' all_events.json | sort
```

| Step | Event | Grants |
|---|---|---|
| 1 | `CreateUser` | The identity |
| 2 | `CreateLoginProfile` | **Console** password — interactive |
| 2′ | `CreateAccessKey` | **Programmatic** key |
| 3 | `AddUserToGroup` / `AttachUserPolicy` | The privileges |

Steps 2 and 2′ are alternatives — which appears answers "how did they access the account they created".

```bash
jq -r 'select(.eventName | test("^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteFlowLogs|DeleteDetector)$"))
  | [.eventTime, .eventName, .userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' \
  all_events.json | sort
```

⚠ Attackers frequently disable logging **after** establishing persistence. Two consequences: check for an event gap after `StopLogging` — anything in it is invisible and needs another source; and the order itself is evidence, since persistence created before the blackout is fully documented.

---

## BEC / invoice fraud

**The function that builds the invoice:**

```
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.functionName, requestParameters.environment
| filter eventSource = "lambda.amazonaws.com"
| filter eventName in ["UpdateFunctionCode","UpdateFunctionConfiguration","CreateFunction","AddPermission"]
| sort eventTime asc
```

`UpdateFunctionConfiguration` — changing an env var holding payment details alters every invoice with no code change and no file artifact.

**Sending channel:** `eventSource = "ses.amazonaws.com"` → `VerifyEmailIdentity`, `VerifyDomainIdentity`, `CreateReceiptRule`, `UpdateReceiptRule` (inbound mail redirected — how the victim's reply is intercepted), `SendEmail`/`SendRawEmail` from an unexpected principal.

**Stored artifacts:** `eventSource = "s3.amazonaws.com"` → `PutObject`, `GetObject`, `DeleteObject`, `PutBucketPolicy`, `PutBucketAcl`.

**Application logs** (`/aws/lambda/<Fn>`):

```
fields @timestamp, @message
| filter @message like /(?i)(iban|account|routing|swift|invoice|bank)/
| sort @timestamp asc
```

**Finding the fraudulent message:** establish the normal shape first, then invert. Rarity is the signal — a fraudulent invoice is sent once, routine notifications repeat.

```
parse @message '"to": "*"' as recipient
| stats count(*) as emails by recipient
| sort emails asc

fields @timestamp, @message
| filter @message not like "@<INTERNAL_DOMAIN>\"}"
| sort @timestamp asc
```

Look for lookalike domains in recipient and body — TLD swap (`.live` for `.com`), plausible compound (`<brand>pay.com`). Cross-reference send time against config changes.

---

## Indicator → campaign attribution

Once you hold concrete artifacts, attribution is an OSINT search, not a deduction. Typosquatted domains are the strongest search terms — unique strings, indexed directly by threat intel.

1. Search each attacker domain verbatim, in quotes, including defanged (`example[.]com`)
2. Search the tool combination as a phrase
3. Search the TTP set by ATT&CK technique IDs — four or five in combination narrows sharply
4. [ATT&CK Campaigns](https://attack.mitre.org/campaigns/) index and vendor research blogs

---

## GuardDuty & VPC Flow Logs

GuardDuty finding names: `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.DetectionMechanism`. Findings are leads pointing at a time window and a principal — prove it in CloudTrail.

VPC Flow Logs: src/dst IP and port, protocol, packet and byte counts, `ACCEPT`/`REJECT`. Use for large outbound transfers (sort by bytes), unexpected destinations, and to confirm connections CloudTrail can't see. No payload.
