# REGULATION DOCUMENT — STRUCTURED SUBMISSION TEMPLATE
# Complete all sections. Do not remove section headers.
# Upload this file via the Rule Authoring Console.

---

ASSET_TYPE: CRYPTO_VDA
# Required. Must match exactly one of: FIAT_WIRE, CRYPTO_VDA, TRADE_FINANCE, FOREX
# If asset type is new, contact system administrator to register it first.

REGULATION_NAME: Prevention of Money Laundering (Maintenance of Records) Amendment Rules 2023
# Full official name of the regulation as it should appear in SAR citations.

REGULATION_SHORT_CODE: PMLA-VDA-2023
# Short identifier used internally. No spaces. Use hyphens.

ISSUING_AUTHORITY: Ministry of Finance, Government of India
# The government body or regulator that issued this document.

EFFECTIVE_DATE: 2023-03-07
# YYYY-MM-DD format.

REPORTING_BODY: FIU-IND
# Body to which SARs under this regulation must be filed.

---

SCOPE:
This amendment extends the scope of the Prevention of Money Laundering Act 2002
to include Virtual Digital Assets (VDA). All reporting entities dealing in VDA
transactions are required to maintain records and report suspicious transactions
to FIU-IND. A VDA is defined as any digital representation of value that can be
digitally traded, transferred, or used for payment.

---

THRESHOLDS:
# List every measurable threshold in this regulation.
# Format: THRESHOLD_NAME | VALUE | UNIT | CONDITION_TYPE
# CONDITION_TYPE must be one of: gt, ge, lt, le, eq, between_exclusive

VDA_REPORTING_THRESHOLD | 1000000 | INR | gt
# Aggregate VDA transactions above INR 10 lakh in a calendar month must be reported.

VDA_VELOCITY_THRESHOLD | 5 | transactions_per_day | gt
# More than 5 VDA transactions per day triggers enhanced monitoring.

VDA_ONCHAIN_HOP_THRESHOLD | 2 | hops | gt
# More than 2 on-chain hops indicates layering behaviour.

---

CONDITIONS:
# List every condition this regulation defines as suspicious.
# Format: CONDITION_NAME | FIELD_PATH | DESCRIPTION

VDA_STRUCTURING | txn.total_amount | Aggregate VDA transactions structured below INR 10 lakh reporting threshold
VDA_UNHOSTED_WALLET | txn.destination_country | Transfer to unhosted or self-custodied wallet with no registered VDA service provider
VDA_MULTI_HOP | crypto_context.on_chain_hops | Multiple on-chain transaction hops to obscure fund origin
VDA_UNREGISTERED_EXCHANGE | crypto_context.exchange_registered_fiu | Transaction routed through exchange not registered with FIU-IND
VDA_RAPID_CONVERSION | crypto_context.conversion_direction | Rapid fiat-to-crypto conversion indicating layering intent

---

REGULATORY_CITATIONS:
# List every section that can be cited in a SAR narrative.
# Format: SECTION_REFERENCE | FULL_CITATION_TEXT

PMLA-2023-S12 | PMLA Section 12 as amended by the Prevention of Money Laundering (Maintenance of Records) Amendment Rules 2023
PMLA-2023-VDA | Prevention of Money Laundering (Maintenance of Records) Amendment Rules 2023 — Virtual Digital Asset Reporting Obligation
FIU-VDA-2023 | FIU-IND Directive on Registration of Virtual Digital Asset Service Providers, December 2023
FATF-VA-2023 | FATF Updated Guidance on Virtual Assets and Virtual Asset Service Providers 2023

---

CONCLUSION_REGULATION_TEXT:
PMLA Section 12 as amended by the Prevention of Money Laundering (Maintenance of Records) Amendment Rules 2023,
which extended reporting obligations to Virtual Digital Assets. FIU-IND notified in accordance with the
FIU-IND Directive on Registration of Virtual Digital Asset Service Providers, December 2023.

---

ADDITIONAL_PROMPT_CONTEXT:
This is a Virtual Digital Asset transaction. The applicable regulatory framework includes the PMLA VDA
Amendment March 2023 and the FIU-IND VDA Service Provider Registration Directive December 2023.
The SAR conclusion must cite these instruments specifically. Do not use generic fiat wire transfer language.
References to destination country should use wallet type terminology not geographic jurisdiction terminology
when destination is UNHOSTED_WALLET.