defmodule Reticulum.Destination do
  @moduledoc """
  Reticulum destination struct
  """

  alias Reticulum.Identity

  defstruct type: nil,
            direction: nil,
            proof_strategy: :none,
            mtu: 0,
            links: [],
            identity: nil,
            name: nil

  def new(direction, type, app_name, identity \\ nil, aspects \\ []) do
    %__MODULE__{direction: direction, type: type, identity: identity}
    |> add_identity()
    |> add_name(app_name, aspects)
  end

  defp add_identity(%__MODULE__{type: :plain, identity: nil} = dest), do: dest

  defp add_identity(%__MODULE__{type: :plain}),
    do: raise("Selected destination type PLAIN cannot hold an identity")

  defp add_identity(%__MODULE__{direction: :in, identity: nil} = dest) do
    %__MODULE__{dest | identity: Identity.new()}
  end

  defp add_identity(%__MODULE__{} = dest), do: dest

  defp add_name(%__MODULE__{identity: nil} = dest, app_name, aspects) do
    %__MODULE__{dest | name: Enum.join([app_name | aspects], ".")}
  end

  defp add_name(%__MODULE__{identity: %Identity{hash: hash}} = dest, app_name, aspects) do
    name =
      [Base.encode16(hash) | Enum.reverse([app_name | aspects])]
      |> Enum.reverse()
      |> Enum.join(".")

    %__MODULE__{dest | name: name}
  end
end
