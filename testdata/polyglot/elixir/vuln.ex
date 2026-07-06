# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
# Never compiled; exists only to be scanned by semgrep.
#
# Elixir DID NOT LAND this session: p/elixir (a thin registry pack) plus
# p/default caught NONE of the plants below. Per the earn-your-slot bar the
# language is not claimed as supported — .ex/.exs stay "unsupported source"
# in skip accounting, and every plant here is an honest PLANT-GAP. Documented
# in docs/coverage.md and the PR, not silently dropped.

defmodule Vuln do
  import Ecto.Query

  def take_input(args), do: List.first(args) || ""

  # PLANT-GAP (elixir-sqli, CWE-89): raw SQL built by interpolation
  def sqli(user_input, repo) do
    query = "SELECT * FROM users WHERE name = '#{user_input}'"
    Ecto.Adapters.SQL.query!(repo, query, [])
  end

  # PLANT-GAP (elixir-cmdi, CWE-78): shell invocation with interpolated input
  def cmdi(user_input) do
    System.cmd("sh", ["-c", "echo #{user_input}"])
  end

  # PLANT-GAP (elixir-atom-exhaustion, CWE-20): untrusted input to String.to_atom
  def to_atom(user_input) do
    String.to_atom(user_input)
  end

  # PLANT-GAP (elixir-code-eval, CWE-95): dynamic code evaluation of input
  def eval(user_input) do
    Code.eval_string(user_input)
  end

  # PLANT-GAP (elixir-unsafe-deserialize, CWE-502): binary_to_term on untrusted data
  def deserialize(bin) do
    :erlang.binary_to_term(bin)
  end

  def main(args) do
    input = take_input(args)
    cmdi(input)
    to_atom(input)
    eval(input)
  end
end
