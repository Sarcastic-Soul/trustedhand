resource "aws_bedrock_guardrail" "g" {
  name                      = "trustedhand"
  description               = "TrustedHand: prompt attacks, scam topics, account and card numbers."
  blocked_input_messaging   = "I cannot help with that message. If someone is pressuring you to move money, please stop and call your son Ravi, or call 1930 (the cyber crime helpline)."
  blocked_outputs_messaging = "I am sorry, I cannot show that. Please ask Ravi if you need help."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "MEDIUM"
      output_strength = "NONE"
    }
  }

  topic_policy_config {
    topics_config {
      name       = "digital-arrest-threats"
      type       = "DENY"
      definition = "Someone posing as police, CBI, customs or a court threatens arrest or a case (digital arrest) and demands money, secrecy or staying on a call."
      examples = [
        "A CBI officer is on video call with me and says I am under digital arrest.",
        "The police told me my Aadhaar was used in a crime and I must not tell my family.",
        "Customs officer says a parcel in my name has drugs and I must pay a fine today.",
        "An ED officer says my name is in a hawala case and I must pay a bail guarantee.",
        "I am being watched on video call by an officer and cannot hang up.",
      ]
    }

    topics_config {
      name       = "safe-account-transfers"
      type       = "DENY"
      definition = "Requests to move money to a 'safe', 'secure', 'RBI verification' or 'government' account to protect it, verify it or clear a case."
      examples = [
        "They told me to transfer my savings to a safe account for RBI verification.",
        "Send all my money to the secure government account so it can be checked.",
        "The officer said the money will be returned after verification if I move it to this account.",
        "Move my fixed deposit to the RBI safe account today.",
        "Transfer two lakh rupees to the verification account they gave me.",
      ]
    }

    topics_config {
      name       = "gift-card-or-crypto-payment"
      type       = "DENY"
      definition = "Requests to pay anyone with gift cards, vouchers, cryptocurrency, bitcoin or USDT."
      examples = [
        "Buy gift cards and read me the codes to clear the fine.",
        "Pay the officer in bitcoin so the case is closed.",
        "Please send USDT to this wallet address for the penalty.",
        "I need to buy Google Play vouchers and share the numbers with them.",
        "They asked me to pay with crypto because it cannot be traced.",
      ]
    }

    topics_config {
      name       = "sharing-otp-pin-passwords"
      type       = "DENY"
      definition = "Messages that share, read out or ask to share an OTP, PIN, CVV, card number, UPI PIN or password."
      examples = [
        "My OTP is 482913, please use it to approve the payment.",
        "The caller wants my UPI PIN, should I tell him?",
        "Here is my card number and CVV so you can pay.",
        "Tell the officer my net banking password so he can check the account.",
        "I will read out the OTP that just came on my phone.",
      ]
    }
  }

  sensitive_information_policy_config {
    regexes_config {
      name           = "bank-account-number"
      description    = "9 to 18 digit bank account numbers"
      pattern        = "\\b[0-9]{9,18}\\b"
      action         = "ANONYMIZE"
      input_action   = "NONE"
      input_enabled  = false
      output_action  = "ANONYMIZE"
      output_enabled = true
    }

    pii_entities_config {
      type           = "CREDIT_DEBIT_CARD_NUMBER"
      action         = "ANONYMIZE"
      input_action   = "NONE"
      input_enabled  = false
      output_action  = "ANONYMIZE"
      output_enabled = true
    }
  }
}

# Frozen version used by the chat proxy and the interceptor.
resource "aws_bedrock_guardrail_version" "v" {
  guardrail_arn = aws_bedrock_guardrail.g.guardrail_arn
  description   = "trustedhand"
  skip_destroy  = false

  # A new version whenever the guardrail itself changes.
  lifecycle {
    replace_triggered_by = [aws_bedrock_guardrail.g]
  }
}

# Reply guardrail: masks account and card numbers only. It has no scam topics,
# because the agent's own warnings ("this looks like a digital arrest scam")
# would trip them and the elder would see a blocked message instead.
resource "aws_bedrock_guardrail" "out" {
  name                      = "trustedhand-out"
  description               = "TrustedHand replies: mask account and card numbers."
  blocked_input_messaging   = "I cannot help with that message."
  blocked_outputs_messaging = "I am sorry, I cannot show that. Please ask Ravi if you need help."

  sensitive_information_policy_config {
    regexes_config {
      name           = "bank-account-number"
      description    = "9 to 18 digit bank account numbers"
      pattern        = "\\b[0-9]{9,18}\\b"
      action         = "ANONYMIZE"
      input_action   = "NONE"
      input_enabled  = false
      output_action  = "ANONYMIZE"
      output_enabled = true
    }

    pii_entities_config {
      type           = "CREDIT_DEBIT_CARD_NUMBER"
      action         = "ANONYMIZE"
      input_action   = "NONE"
      input_enabled  = false
      output_action  = "ANONYMIZE"
      output_enabled = true
    }
  }
}

resource "aws_bedrock_guardrail_version" "out" {
  guardrail_arn = aws_bedrock_guardrail.out.guardrail_arn
  description   = "trustedhand-out"
  skip_destroy  = false

  lifecycle {
    replace_triggered_by = [aws_bedrock_guardrail.out]
  }
}
