defmodule Reticulum.Crypto do
  @moduledoc """
  Crypto primitives for Reticulum
  """

  @hash_len 32

  @doc """
  https://soatok.blog/2021/11/17/understanding-hkdf/
  https://en.wikipedia.org/wiki/HKDF
  """
  def hkdf(ikm, salt \\ <<>>, info \\ <<>>, len \\ 32)
      when len > 0 and is_binary(ikm) and byte_size(ikm) > 0 do
    salt
    |> hkdf_extract(ikm)
    |> hkdf_expand(info, len)
  end

  defp hkdf_extract(<<>>, ikm), do: hkdf_extract(<<0::size(256)>>, ikm)
  defp hkdf_extract(salt, ikm), do: hmac(salt, ikm)

  defp hkdf_expand(prk, info, len) do
    {<<okm::binary-size(len), _rest::binary>>, _t} =
      Enum.reduce(1..ceil(len / @hash_len), {<<>>, <<>>}, fn i, {okm, t} ->
        t = hmac(prk, t <> info <> <<i>>)
        {okm <> t, t}
      end)

    okm
  end

  def sha256(data) do
    :crypto.hash(:sha256, data)
  end

  def hmac(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end

  def ed25519 do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  def x25519 do
    :crypto.generate_key(:eddh, :x25519)
  end

  def compute(%{sec: sec, pub: pub}) do
    :crypto.compute_key(:eddh, pub, sec, :x25519)
  end

  def sign(key, message) do
    :crypto.sign(:eddsa, :none, message, [key, :ed25519])
  end

  def validate(key, message, signature) do
    :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519])
  end
end
