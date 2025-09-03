
##  Vulnerability Report: Remanence and Trust-Boundary Violations in Google Persistent Disk


Multiple trust-boundary violations and a confirmed zero-on-allocate failure are present in **Google Cloud Persistent Disk (PD)**. The findings demonstrate that malformed SCSI UNMAP payloads can be accepted and acted upon, and that freed blocks may be reissued without sanitization — violating LBPRZ guarantees and exposing residual data.

---

###  Affected Component

- **Target:** Google Persistent Disk (GCP PD)
- **Interface:** SCSI UNMAP command via virtio-scsi passthrough
- **Environment:** Linux guest (root), using `sg_raw` and custom harnesses
- **Backend Behavior:** GCP PD’s discard logic and allocator reuse path

---

###  Vulnerability Class

| Bug Type                         | Component Impacted              | Severity |
|----------------------------------|----------------------------------|----------|
| Zero-on-allocate failure         | PD allocator / discard logic     | High     |
| Partial descriptor execution     | SCSI UNMAP parser                | Medium   |
| Header overclaim acceptance      | SCSI UNMAP parser                | Medium   |
| Non-atomic discard under load    | PD discard queue / timing logic | Medium   |
| Descriptor count mismatch        | SCSI UNMAP parser                | Medium   |

---

###  Proven Findings

#### 1. **Remanence in Freed Blocks**
- **Setup:** Seeded region with `0xA5`, issued UNMAP, reallocated partial range.
- **Result:** Unwritten portion returned `0xA5` on read.
- **Violation:** Device advertised `LBPRZ=1`; expected zeros.
- **Impact:** Data confidentiality breach; stale data exposed.

#### 2. **Partial Execution of Malformed Payloads**
- **Setup:** UNMAP with valid descriptor followed by malformed ones.
- **Result:** Device returned `SCSI: Good`; valid range zeroed.
- **Violation:** Spec expects atomic failure on malformed payloads.
- **Impact:** Trust-boundary violation; backend executes partial payload.

#### 3. **Header Overclaim Accepted**
- **Setup:** PLEN/BDDL claimed more than delivered; only valid descriptor present.
- **Result:** Device accepted and zeroed target.
- **Violation:** Length mismatch should trigger rejection.
- **Impact:** Parser leniency; potential buffer mis-accounting.

#### 4. **Discard/Write Race Under Load**
- **Setup:** Concurrent UNMAPs and writes; stress harness active.
- **Result:** Valid UNMAPs returned `Good`, but read-back showed non-zero.
- **Violation:** Discard should be atomic and immediate.
- **Impact:** Timing window for stale data exposure.

#### 5. **Descriptor Count Mismatch**
- **Setup:** BDDL = 1, PLEN = 256 bytes (16 descriptors sent).
- **Result:** Signs of backend acting on descriptors beyond declared count.
- **Violation:** Parser should loop only over declared descriptors.
- **Impact:** Heap overwrite candidate; potential memory corruption.


### 1) Partial Descriptor Execution (**GOOD → BAD**)

**What proves it:** in the **AT1** mix (valid descriptor first, then an out-of-range one you “hide” later in the payload), our seeded read-backs show the valid extent is **ZEROED** while the malformed one is ignored, and the command still returns **SCSI: Good**. our notes spell it out: “Good; good range ZEROED; bad ignored → partial apply.”

**Why it matters:** This confirms **non–all-or-nothing** semantics: the backend **executes the valid part** even when the overall payload is malformed, i.e., a **trust-boundary violation**.

---

### 2) Header Overclaim Accepted

**What proves it:** we intentionally **lied in the header** and the device still accepted and acted on the request:

* **BDDL too large vs. actual data** → **GOOD** (target accepts truncated body).
* **Trailing junk** beyond the declared descriptor(s) → **GOOD** (target ignores extra tail).

**Why it matters:** The backend is using the **actual dxfer** and/or envelope more than the header’s internal lengths, a **length-consistency violation** (classic precondition for overread/mis-accounting bugs).

---

### 3) Zero-on-Allocate Failure (**Remanence**)

**What proves it:** our “smoking-gun” run:

1. Seed region with **0xA5** → send UNMAP → device rejects with **Check Condition (Parameter list length error)**.
2. Immediate and delayed reads of the freed space still return **0xA5**.
3. Reallocate only part of it with **0x5A**: the written slice reads back as **0x5A**, but the **unwritten hole** still contains **0xA5**, and our verifier flags: “**zero-on-allocate failed (unwritten hole is non-zero)**.”  

**Why it matters:** On a device advertising **LBPRZ=1**, newly allocated (previously unmapped) blocks **must read as zeros**; our didn’t → **data confidentiality breach**.

---

### 4) Discard/Write Race Under Load

**What proves it:** during our concurrency harness runs, our log **thousands** of cases where a **valid UNMAP** returns **Good** but read-back shows **non-zero** bytes (post-UNMAP anomalies) — exactly the signature of **non-atomic discard** under pressure.(e.g., “VALID UNMAP left 131072 non-zero bytes at …”).
**3,889** valid-UNMAP failures vs. only 4 “canary-zero” hits for malformed payloads.

**Why it matters:** this is a **timing window** where discards race with writes → stale data exposure / discard bypass, violating expected semantics.

---

### 5) Descriptor Count Mismatch (**BDDL vs. PLEN**)

**What proves it:** Our analysis concludes the backend **ignores the declared descriptor count (BD-DL)** and even its VPD “max=1” claim **when the outer envelope is valid**, and will **parse/act on all descriptors present** (i.e., it trusts PLEN/dxfer).
We also demonstrated acceptance of **>1 descriptor** despite VPD’s 1-descriptor limit (“2 descriptors (exceeding VPD limit) → Good”).

**Why it matters:** If allocation is sized for **BDDL** but parsing walks **PLEN/dxfer**, we have a **heap-overwrite candidate** (and, at minimum, mis-accounting).

---

### 6) Malformed Descriptor Acceptance (**Reserved bits, NUM=0, misalignment**)

**What proves it:** our fuzz matrix shows the target is **lenient**:

* **Reserved fields non-zero** → **Accepted (Good)**.
* **Unaligned LBAs (+1..+7)** → **Good** (no alignment enforcement).
* **Length = 0** (NUM=0) → **Good** (treated as no-op).

**Why it matters:** This **parser leniency** breaks spec expectations and **widens the fuzzing surface** for semantic bugs and mis-accounting.

---

### 7) Cross-Reuse Remanence under Allocator Churn

**What proves it:** our harness includes **cross-reuse** and **pressure** toggles to force the allocator to recycle physical blocks. It then checks **\[VERIFY-HOLE] nonzero\_bytes** in newly allocated **unwritten** gaps; when this trips, it prints “**RESIDUAL-LEAK DETECTED** … hexdump of stale data” — our proof of **zero-on-reuse** failure under churn. 
You also note that raising `--pressure` increases reproducibility (allocator churn) — exactly the condition for **cross-reuse** leakage.

Risk assessment

Impact today: The good-then-bad acceptance lets a privileged initiator hide malformed tails while still achieving targeted discards. That’s a robustness & spec-compliance problem rather than an immediate integrity or confidentiality break.

Potential pivot: If a header/dxfer discrepancy is indeed accepted in some codepath, that’s a trust violation at the parser boundary. While we did not observe memory corruption, this class is a classic trigger for state confusion and needs deeper differential testing.

<img width="1360" height="768" alt="2025-09-03 04_14_31-Greenshot" src="https://github.com/user-attachments/assets/bb835101-b397-4be2-ae21-6841a6d4e2dd" />
<img width="1360" height="768" alt="2025-09-03 04_14_15-Greenshot" src="https://github.com/user-attachments/assets/7863fb74-dd66-4951-8c66-a8ff1ec30518" />
<img width="1360" height="768" alt="2025-09-03 04_08_23-Greenshot" src="https://github.com/user-attachments/assets/62d3101e-bf15-4999-964d-f5c5cb199758" />
<img width="1360" height="768" alt="2025-09-03 03_54_48-Greenshot" src="https://github.com/user-attachments/assets/897597f9-69de-4762-a78a-2c65878ced3b" />
<img width="1360" height="768" alt="2025-09-03 03_34_47-Greenshot" src="https://github.com/user-attachments/assets/5f9f81e2-4364-44c7-b8c3-adef91350f75" />
<img width="1360" height="768" alt="2025-09-03 03_31_56-Greenshot" src="https://github.com/user-attachments/assets/1cce6181-8257-4782-86c6-8b2c65f9c73f" />
<img width="1360" height="768" alt="2025-09-03 03_30_35-Greenshot" src="https://github.com/user-attachments/assets/fb9baf8e-8eeb-4ff8-9714-91039f168f9d" />
<img width="1360" height="768" alt="2025-09-03 03_27_43-Greenshot" src="https://github.com/user-attachments/assets/612d20ec-4bb7-486d-9d9c-74d29aa80837" />
<img width="1360" height="768" alt="2025-09-03 03_21_32-Greenshot" src="https://github.com/user-attachments/assets/64dfb01c-315f-42dd-8bdd-e8b17e8a7738" />
<img width="1360" height="768" alt="2025-09-03 03_05_08-Greenshot" src="https://github.com/user-attachments/assets/f4f36478-2d37-4bf1-913d-3fa206a6b543" />
<img width="1360" height="768" alt="2025-09-03 03_02_03-Greenshot" src="https://github.com/user-attachments/assets/0e0f4b01-f744-4c2a-93c8-9e8aaebca373" />
<img width="1360" height="768" alt="2025-09-03 02_59_38-Greenshot" src="https://github.com/user-attachments/assets/b847b1ec-58f3-4171-9b64-367479af7953" />
<img width="1360" height="768" alt="2025-09-03 02_52_00-Greenshot" src="https://github.com/user-attachments/assets/abe3184e-1533-4f23-8e4e-f02fcfc210c3" />
<img width="1360" height="768" alt="2025-09-03 00_12_48-Greenshot" src="https://github.com/user-attachments/assets/0eb318b8-fe7a-45c2-a6a3-f97b03392d91" />
<img width="1360" height="768" alt="2025-09-03 00_05_42-Greenshot" src="https://github.com/user-attachments/assets/ab17d87b-e262-44a5-909b-6be1e8ea41e0" />
<img width="1360" height="768" alt="2025-09-02 23_52_15-Greenshot" src="https://github.com/user-attachments/assets/baa5c9a8-2b03-4eba-9645-aaa37c35c844" />
<img width="1360" height="768" alt="2025-09-02 23_44_03-Greenshot" src="https://github.com/user-attachments/assets/068a60f9-788b-4e31-8822-b69c3059e0c1" />
<img width="1360" height="768" alt="2025-09-02 23_43_39-Greenshot" src="https://github.com/user-attachments/assets/464b2601-871f-42df-8a50-8e35c68739c3" />
<img width="1360" height="768" alt="2025-09-02 22_54_51-Greenshot" src="https://github.com/user-attachments/assets/fc47e42f-4eef-4c52-b097-1ddacc128b9e" />
<img width="1360" height="768" alt="2025-09-02 21_55_33-Greenshot" src="https://github.com/user-attachments/assets/b559abe2-9147-41ff-b24a-a4506c1fec17" />
<img width="1360" height="768" alt="2025-09-02 21_50_30-Greenshot" src="https://github.com/user-attachments/assets/17af98ea-9786-4e1f-9c68-cbb770f10fba" />
<img width="1360" height="768" alt="2025-09-02 21_42_55-Greenshot" src="https://github.com/user-attachments/assets/10950b6b-d25e-48f5-8c6f-e5f8a3c7e206" />
<img width="1360" height="768" alt="2025-09-02 21_42_42-Greenshot" src="https://github.com/user-attachments/assets/59b6ccc0-1a04-477b-9066-ba4b5ce07f13" />
<img width="1360" height="768" alt="2025-09-02 21_42_29-Greenshot" src="https://github.com/user-attachments/assets/0983aa16-5816-4cda-8538-811389e38780" />
<img width="1360" height="768" alt="2025-09-02 21_42_14-Greenshot" src="https://github.com/user-attachments/assets/f415562d-6966-4a7c-82d2-06da6f53f939" />
<img width="1360" height="768" alt="2025-09-02 21_34_34-Greenshot" src="https://github.com/user-attachments/assets/7cfeef32-9b91-4ad0-9c8d-ac2a8f57e380" />
<img width="1360" height="768" alt="2025-09-02 21_33_56-Greenshot" src="https://github.com/user-attachments/assets/2e27cbca-d4f4-4fea-9e3b-af4ca23496de" />
<img width="1360" height="768" alt="2025-09-02 21_33_41-Greenshot" src="https://github.com/user-attachments/assets/8d31e935-6058-47b1-8dc5-316bbca80d04" />
<img width="1360" height="768" alt="2025-09-02 21_33_21-Greenshot" src="https://github.com/user-attachments/assets/43466547-de05-4f06-9077-d7455314167e" />
<img width="1360" height="768" alt="2025-09-02 19_19_13-Greenshot" src="https://github.com/user-attachments/assets/85684043-ba80-4112-b4c6-757f5a52d10d" />
<img width="1360" height="768" alt="2025-09-02 19_19_00-Greenshot" src="https://github.com/user-attachments/assets/14a4babd-7d8d-42c6-a0b3-9da645021390" />
<img width="1360" height="768" alt="2025-09-02 19_18_41-Greenshot" src="https://github.com/user-attachments/assets/10ab1f61-b978-44f8-8f2a-5e2bb45a7dc8" />
<img width="1360" height="768" alt="2025-09-02 17_50_27-Greenshot" src="https://github.com/user-attachments/assets/688213db-4fa8-4036-a06a-719c118848e1" />
<img width="1360" height="768" alt="2025-09-02 17_50_13-Greenshot" src="https://github.com/user-attachments/assets/2f18b531-257a-4b19-aa8c-c68a42379b05" />
<img width="1360" height="768" alt="2025-09-02 17_49_58-Greenshot" src="https://github.com/user-attachments/assets/1c816013-00d7-4974-bfd1-3e291d0ae660" />
<img width="1360" height="768" alt="2025-09-02 17_49_43-Greenshot" src="https://github.com/user-attachments/assets/dd096161-5457-4eb6-aa6d-7a859037181d" />
<img width="1360" height="768" alt="2025-09-02 17_49_30-Greenshot" src="https://github.com/user-attachments/assets/5ae77b36-1913-42cc-ba95-7c026811fd67" />
<img width="1360" height="768" alt="2025-09-02 17_49_18-Greenshot" src="https://github.com/user-attachments/assets/28a7c5f9-9432-4df5-a7da-90c018b0edfa" />
<img width="1360" height="768" alt="2025-09-02 17_49_06-Greenshot" src="https://github.com/user-attachments/assets/59cc33d0-6765-4f71-a57b-54580cbfd76b" />
<img width="1360" height="768" alt="2025-09-02 17_48_48-Greenshot" src="https://github.com/user-attachments/assets/075182ce-38d0-460b-a7e1-cc6b86eb68d9" />
<img width="1360" height="768" alt="2025-09-02 17_41_15-Greenshot" src="https://github.com/user-attachments/assets/a59e6144-66d1-4ff7-ad4c-2842c4678191" />
<img width="1360" height="768" alt="2025-09-02 17_41_03-Greenshot" src="https://github.com/user-attachments/assets/248dd0b4-c723-4384-8ff6-6faed23e5514" />
<img width="1360" height="768" alt="2025-09-02 17_40_48-Greenshot" src="https://github.com/user-attachments/assets/03394a8a-f88a-4fc0-aec2-d03b4def9a4d" />
<img width="1360" height="768" alt="2025-09-02 17_40_32-Greenshot" src="https://github.com/user-attachments/assets/f5e51880-0237-4cd4-a200-ed4472126181" />
<img width="1360" height="768" alt="2025-09-02 17_13_18-Greenshot" src="https://github.com/user-attachments/assets/cfd539a4-2e34-460e-b862-a006b7eaaab7" />
<img width="1360" height="768" alt="2025-09-02 17_12_42-Greenshot" src="https://github.com/user-attachments/assets/2443acb9-cc5c-44d9-8b00-72f60c13378e" />
<img width="1360" height="768" alt="2025-09-02 02_41_05-Greenshot" src="https://github.com/user-attachments/assets/4edc22f2-4ae9-409a-90e9-d9b0237b493b" />
<img width="1360" height="768" alt="2025-09-02 02_40_42-Greenshot" src="https://github.com/user-attachments/assets/785ac788-41e1-40b6-9653-94359ca19d3c" />
<img width="1360" height="768" alt="2025-09-02 01_02_00-Greenshot" src="https://github.com/user-attachments/assets/839c9398-6e67-4168-a7ff-94289a3bd532" />
<img width="1360" height="768" alt="2025-09-01 20_16_37-Greenshot" src="https://github.com/user-attachments/assets/ddca3555-963e-4700-aed1-f848aafccf61" />
<img width="1360" height="768" alt="2025-09-01 20_16_25-Greenshot" src="https://github.com/user-attachments/assets/1558fa3c-7de1-4e5e-a930-b7eb8b617ab3" />
<img width="1360" height="768" alt="2025-09-01 20_16_14-Greenshot" src="https://github.com/user-attachments/assets/14e51834-7227-4ca7-94bc-4d1803eff003" />
<img width="1360" height="768" alt="2025-09-01 20_16_00-Greenshot" src="https://github.com/user-attachments/assets/6b823ef8-6e05-49e3-9d0b-67b446f4d113" />
<img width="1360" height="768" alt="2025-09-01 19_10_13-Greenshot" src="https://github.com/user-attachments/assets/dab8e493-c46f-4014-b15e-396663a814fa" />
<img width="1360" height="768" alt="2025-09-01 19_09_49-Greenshot" src="https://github.com/user-attachments/assets/284f3593-4842-4ab1-b4e1-d84c8863d448" />
<img width="1360" height="768" alt="2025-09-01 19_09_19-Greenshot" src="https://github.com/user-attachments/assets/071d8fce-0226-49a5-abfb-5134e153c623" />
<img width="1360" height="768" alt="2025-09-01 18_42_12-Greenshot" src="https://github.com/user-attachments/assets/4f39b668-8a91-43b7-a9f4-72b6ad524a02" />
<img width="1360" height="768" alt="2025-09-01 18_41_59-Greenshot" src="https://github.com/user-attachments/assets/898722ef-9171-4ec3-beb3-75e6035b0158" />
<img width="1360" height="768" alt="2025-09-01 18_41_41-Greenshot" src="https://github.com/user-attachments/assets/0eca3ee4-77d1-4351-8189-001e12662ca8" />
<img width="1360" height="768" alt="2025-09-01 18_41_26-Greenshot" src="https://github.com/user-attachments/assets/06693103-699b-4c64-a6cc-cc1b17e64281" />
<img width="1360" height="768" alt="2025-09-01 18_41_03-Greenshot" src="https://github.com/user-attachments/assets/cf2ad82b-3a05-416e-932e-79985e80f952" />
<img width="1360" height="768" alt="2025-09-03 15_34_55-Greenshot" src="https://github.com/user-attachments/assets/ad4078fa-0cbf-4bd9-b989-8a4a46bb056b" />
<img width="1360" height="768" alt="2025-09-03 15_34_39-Greenshot" src="https://github.com/user-attachments/assets/53a3b167-b663-40a4-a76a-ab24e06881dd" />
<img width="1360" height="768" alt="2025-09-03 14_18_08-Greenshot" src="https://github.com/user-attachments/assets/6be6f6c2-5d7f-41a4-be3b-4f6f3321d6ae" />
<img width="1360" height="768" alt="2025-09-03 14_15_19-Greenshot" src="https://github.com/user-attachments/assets/ebdcb6e0-d64e-42b5-ad79-021ef6a863c6" />
<img width="1360" height="768" alt="2025-09-03 14_13_59-Greenshot" src="https://github.com/user-attachments/assets/637d7816-2d47-46fb-99d0-a9b21b88466e" />
<img width="1360" height="768" alt="2025-09-03 14_13_35-Greenshot" src="https://github.com/user-attachments/assets/33c5a6f2-b799-4d4e-b3df-0db08e1cf5b1" />
<img width="1360" height="768" alt="2025-09-03 04_15_10-Greenshot" src="https://github.com/user-attachments/assets/f8687df0-6f82-4f8c-850f-a60c30981b1d" />
<img width="1360" height="768" alt="2025-09-03 04_14_59-Greenshot" src="https://github.com/user-attachments/assets/134e3f8a-807b-4897-976f-f2d79f614571" />
<img width="1360" height="768" alt="2025-09-03 04_14_46-Greenshot" src="https://github.com/user-attachments/assets/c8167ee6-d277-408d-8d72-2402fc686704" />


