defmodule Reticulum.Packet do
  @moduledoc """
  https://reticulum.network/manual/understanding.html#wire-format
  """
  defstruct ifac: nil,
            propagation: nil,
            destination: nil,
            type: nil,
            hops: 0,
            addresses: [],
            context: nil,
            data: nil

  def encode(%__MODULE__{} = packet) do
    <<
      ifac(packet.ifac)::integer-size(1),
      length(packet.addresses) - 1::integer-size(1),
      propagation(packet.propagation)::integer-size(2),
      destination(packet.destination)::integer-size(2),
      packet_type(packet.type)::integer-size(2),
      packet.hops::integer-size(8),
      Enum.join(packet.addresses, "")::binary,
      packet.context::bytes-size(1),
      packet.data::binary
    >>
  end

  def decode(
        <<ifac::integer-size(1), header::integer-size(1), prop::integer-size(2),
          dest::integer-size(2), type::integer-size(2), hops::integer-size(8),
          addresses::bytes-size(16 * (header + 1)), context::bytes-size(1), data::binary>>
      ) do
    %__MODULE__{
      ifac: ifac(ifac),
      propagation: propagation(prop),
      destination: destination(dest),
      type: packet_type(type),
      hops: hops,
      addresses: addresses(addresses),
      context: context,
      data: data
    }
  end

  defp ifac(0), do: :open
  defp ifac(1), do: :auth
  defp ifac(:open), do: 0
  defp ifac(:auth), do: 1

  defp propagation(0b00), do: :broadcast
  defp propagation(0b01), do: :transport
  defp propagation(:broadcast), do: 0b00
  defp propagation(:transport), do: 0b01

  defp destination(0b00), do: :single
  defp destination(0b01), do: :group
  defp destination(0b10), do: :plain
  defp destination(0b11), do: :link
  defp destination(:single), do: 0b00
  defp destination(:group), do: 0b01
  defp destination(:plain), do: 0b10
  defp destination(:link), do: 0b11

  defp packet_type(0b00), do: :data
  defp packet_type(0b01), do: :announce
  defp packet_type(0b10), do: :link_request
  defp packet_type(0b11), do: :proof
  defp packet_type(:data), do: 0b00
  defp packet_type(:announce), do: 0b01
  defp packet_type(:link_request), do: 0b10
  defp packet_type(:proof), do: 0b11

  defp addresses(address) when byte_size(address) == 16, do: [address]

  defp addresses(<<address1::binary-size(16), address2::binary-size(16)>>),
    do: [address1, address2]
end
