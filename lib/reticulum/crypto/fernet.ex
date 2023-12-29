defmodule Reticulum.Crypto.Fernet do
  @moduledoc """
  This module provides a slightly modified implementation of the Fernet spec found at:
  https://github.com/fernet/spec/blob/master/Spec.md

  According to the spec, a Fernet token includes a one byte VERSION and eight byte TIMESTAMP field
  at the start of each token. These fields are not relevant to Reticulum. They are therefore
  stripped from this implementation, since they incur overhead and leak initiator metadata.
  """
  alias Reticulum.Crypto

  defstruct [:sig_key, :enc_key]

  def new(<<enc_key::binary-size(16), sig_key::binary-size(16)>>) do
    %__MODULE__{sig_key: sig_key, enc_key: enc_key}
  end

  def sig_valid?(%__MODULE__{sig_key: sig_key}, token) do
    # last 32 bytes is the signature
    {cipher_text, received_sig} = String.split_at(token, -32)
    expected_sig = Crypto.hmac(sig_key, cipher_text)

    received_sig == expected_sig
  end

  def encrypt(%__MODULE__{enc_key: enc_key, sig_key: sig_key}, plain_text)
      when is_binary(plain_text) do
    # random IV
    iv = :crypto.strong_rand_bytes(16)

    # AES encrypt
    cipher_text =
      :crypto.crypto_one_time(:aes_128_cbc, enc_key, iv, plain_text,
        encrypt: true,
        padding: :pkcs_padding
      )

    # calculate signature
    signature = Crypto.hmac(sig_key, iv <> cipher_text)

    # construct final token
    iv <> cipher_text <> signature
  end

  def decrypt(%__MODULE__{enc_key: key} = context, cipher_text) when is_binary(cipher_text) do
    if sig_valid?(context, cipher_text) do
      <<iv::binary-size(16), token::binary>> = cipher_text
      {cipher_text, _signature} = String.split_at(token, -32)

      :crypto.crypto_one_time(:aes_128_cbc, key, iv, cipher_text,
        encrypt: false,
        padding: :pkcs_padding
      )
    else
      raise "Invalid signature"
    end
  end
end
