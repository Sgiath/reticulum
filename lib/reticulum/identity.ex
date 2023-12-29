defmodule Reticulum.Identity do
  @moduledoc """
  Reticulum identity
  """

  alias Reticulum.Crypto
  alias Reticulum.Crypto.Fernet

  defstruct [:enc_sec, :enc_pub, :sig_sec, :sig_pub, :hash]

  def new(opts \\ []) do
    gen_keys = Keyword.get(opts, :gen_keys, true)

    %__MODULE__{}
    |> maybe_gen_keys(gen_keys)
    |> update_hash()
  end

  defp maybe_gen_keys(%__MODULE__{} = identity, false), do: identity

  defp maybe_gen_keys(%__MODULE__{} = identity, true) do
    identity
    |> gen_enc_key()
    |> gen_sig_key()
  end

  def gen_enc_key(%__MODULE__{} = identity) do
    {pub, sec} = Crypto.x25519()
    %__MODULE__{identity | enc_sec: sec, enc_pub: pub}
  end

  def gen_sig_key(%__MODULE__{} = identity) do
    {pub, sec} = Crypto.ed25519()
    %__MODULE__{identity | sig_sec: sec, sig_pub: pub}
  end

  def update_hash(%__MODULE__{enc_pub: key} = identity) do
    <<hash::binary-size(16), _rest::binary>> = Crypto.sha256(key)
    %__MODULE__{identity | hash: hash}
  end

  def encrypt(%__MODULE__{enc_pub: enc_pub, hash: hash}, plain_text) do
    {ephemeral_pub, ephemeral_sec} = Crypto.x25519()

    cipher_text =
      %{sec: ephemeral_sec, pub: enc_pub}
      |> Crypto.compute()
      |> Crypto.hkdf(hash)
      |> Fernet.new()
      |> Fernet.encrypt(plain_text)

    ephemeral_pub <> cipher_text
  end

  def decrypt(
        %__MODULE__{enc_sec: enc_sec, hash: hash},
        <<ephemeral_pub::binary-size(32), cipher_text::binary>>
      ) do
    %{sec: enc_sec, pub: ephemeral_pub}
    |> Crypto.compute()
    |> Crypto.hkdf(hash)
    |> Fernet.new()
    |> Fernet.decrypt(cipher_text)
  end

  def sign(%__MODULE__{sig_sec: key}, message) do
    Crypto.sign(key, message)
  end

  def validate(%__MODULE__{sig_pub: key}, message, signature) do
    Crypto.validate(key, message, signature)
  end
end
