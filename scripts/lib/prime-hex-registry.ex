defmodule AutoAPI.HexRegistryPrefetch do
  @moduledoc false

  # Hex's offline resolver also asks for registry records of optional packages
  # that do not appear as selected lock entries (for example Sentry's igniter).
  # Read the existing lock with Mix; do not resolve, compile, or change it here.
  def packages(lock) when is_map(lock) do
    lock
    |> Enum.flat_map(fn
      {_app, {:hex, name, _version, _checksum, _managers, deps, repo, _outer}} ->
        [{repo, to_string(name)} | Enum.map(deps, fn {app, _requirement, options} ->
          {Keyword.get(options, :repo, repo), to_string(Keyword.get(options, :hex, app))}
        end)]
      {_app, value} when is_tuple(value) and elem(value, 0) == :hex ->
        raise "unsupported Hex lock entry"
      _ -> []
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  def run(paths) when paths != [] do
    Mix.start()
    {:ok, _} = Application.ensure_all_started(:hex)
    packages = paths |> Enum.flat_map(&packages(Mix.Dep.Lock.read(&1))) |> Enum.uniq()
    if length(packages) > 2000, do: raise("Hex registry prefetch exceeds 2000 packages")
    Hex.Registry.Server.open()
    try do
      Hex.Registry.Server.prefetch(packages)
      Enum.each(packages, fn {repo, name} ->
        case Hex.Registry.Server.versions(repo, name) do
          {:ok, [_ | _]} -> :ok
          _ -> raise "Hex registry record unavailable for #{repo}/#{name}"
        end
      end)
      Hex.Registry.Server.persist()
    after
      Hex.Registry.Server.close()
    end
  end
end
