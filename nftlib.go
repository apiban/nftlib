/*
NFTLIB - exec commands to work with NFTABLES
The MIT License (MIT)

Copyright (c) 2025 Fred Posner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package nftlib

import (
	"errors"
	"os/exec"

	"github.com/tidwall/gjson"
)

type NFTABLES struct {
	Table    string   `json:"table"`
	Family   string   `json:"family"`
	Version  string   `json:"version"`
	Set      string   `json:"set"`
	Elements []string `json:"elements"`
}

type NFTCHAINDETAILS struct {
	Table  string `json:"table"`
	Family string `json:"family"`
	Chain  string `json:"chain"`
	Hook   string `json:"hook"`
	Type   string `json:"type"`
}

type NFTTABLEDETAILS struct {
	Table  string `json:"table"`
	Family string `json:"family"`
	Handle int    `json:"handle"`
}

// nft add set
func NftAddSet(data NFTCHAINDETAILS, setname string) error {
	args := []string{"add", "set", data.Family, data.Table, setname, "{ type ipv4_addr; }"}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

// nft add v6 set
func NftAddv6Set(data NFTCHAINDETAILS, setname string) error {
	if data.Family != "inet" {
		return errors.New("family does not support ipv6")
	}

	args := []string{"add", "set", data.Family, data.Table, setname, "{ type ipv6_addr; }"}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

// nft list add element to set
func NftAddSetElement(data NFTABLES, ipaddress string) error {
	args := []string{"add", "element", data.Family, data.Table, data.Set, "{", ipaddress, "}"}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

func NftAddSetRuleInput(data NFTCHAINDETAILS, setname string) error {
	args := []string{"add", "rule", data.Family, data.Table, data.Chain, "ip", "saddr", "@" + setname, "drop"}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

func NftAddSetRuleOutput(data NFTCHAINDETAILS, setname string) error {
	args := []string{"add", "rule", data.Family, data.Table, data.Chain, "ip", "daddr", "!=", "@" + setname, "accept"}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

// nft list delete element from set
func NftDelSetElement(data NFTABLES, ipaddress string) error {
	args := []string{"delete", "element", data.Family, data.Table, data.Set, "{", ipaddress, "}"}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

// nft flush set
func NftFlushSet(data NFTABLES) error {
	args := []string{"flush", "set", data.Family, data.Table, data.Set}
	nft := exec.Command("nft", args...)
	if err := nft.Run(); err != nil {
		return err
	}

	return nil
}

// list filter type chains
func NftGetChainDetails(chainname string) (NFTCHAINDETAILS, error) {
	var chaindetails NFTCHAINDETAILS
	args := []string{"-j", "list", "chains"}
	response, err := exec.Command("nft", args...).Output()
	if err != nil {
		return chaindetails, err
	}

	if !gjson.Valid(string(response)) {
		return chaindetails, errors.New("invalid json response")
	}

	chains := gjson.Get(string(response), "nftables.#(chain.name==\""+chainname+"\").chain")
	if !chains.Exists() {
		return chaindetails, errors.New("chain not found")
	}

	family := gjson.Get(string(response), "nftables.#(chain.name==\""+chainname+"\").chain.family")
	if !family.Exists() {
		return chaindetails, errors.New("cannot get chain family")
	}

	table := gjson.Get(string(response), "nftables.#(chain.name==\""+chainname+"\").chain.table")
	if !table.Exists() {
		return chaindetails, errors.New("cannot get chain table")
	}

	hook := gjson.Get(string(response), "nftables.#(chain.name==\""+chainname+"\").chain.hook")
	if !hook.Exists() {
		return chaindetails, errors.New("cannot get chain hook")
	}

	chaintype := gjson.Get(string(response), "nftables.#(chain.name==\""+chainname+"\").chain.type")
	if !chaintype.Exists() {
		return chaindetails, errors.New("cannot get chain type")
	}

	chaindetails.Family = family.String()
	chaindetails.Table = table.String()
	chaindetails.Hook = hook.String()
	chaindetails.Chain = chainname
	chaindetails.Type = chaintype.String()

	return chaindetails, nil
}

// list filter type chains
func NftGetFilterChains() ([]string, error) {
	var nftchains []string
	args := []string{"-j", "list", "chains"}
	response, err := exec.Command("nft", args...).Output()
	if err != nil {
		return nftchains, err
	}

	if !gjson.Valid(string(response)) {
		return nftchains, errors.New("invalid json response")
	}

	chains := gjson.Get(string(response), "nftables.#(chain.type==\"filter\")#.chain.name")
	if chains.Exists() {
		chains.ForEach(func(key, value gjson.Result) bool {
			nftchains = append(nftchains, value.String())
			return true
		})
	} else {
		return nftchains, errors.New("no filter chains found")
	}

	return nftchains, nil
}

// list input hook chains
func NftGetInputChains() ([]string, error) {
	var nftchains []string
	args := []string{"-j", "list", "chains"}
	response, err := exec.Command("nft", args...).Output()
	if err != nil {
		return nftchains, err
	}

	if !gjson.Valid(string(response)) {
		return nftchains, errors.New("invalid json response")
	}

	chains := gjson.Get(string(response), "nftables.#(chain.hook==\"input\")#.chain.name")
	if chains.Exists() {
		chains.ForEach(func(key, value gjson.Result) bool {
			nftchains = append(nftchains, value.String())
			return true
		})
	} else {
		return nftchains, errors.New("no input hook chains found")
	}

	return nftchains, nil
}

// list output hook chains
func NftGetOutputChains() ([]string, error) {
	var nftchains []string
	args := []string{"-j", "list", "chains"}
	response, err := exec.Command("nft", args...).Output()
	if err != nil {
		return nftchains, err
	}

	if !gjson.Valid(string(response)) {
		return nftchains, errors.New("invalid json response")
	}

	chains := gjson.Get(string(response), "nftables.#(chain.hook==\"output\")#.chain.name")
	if chains.Exists() {
		chains.ForEach(func(key, value gjson.Result) bool {
			nftchains = append(nftchains, value.String())
			return true
		})
	} else {
		return nftchains, errors.New("no output hook chains found")
	}

	return nftchains, nil
}

// list tables
func NftGetTables() ([]string, error) {
	var nfttables []string
	args := []string{"-j", "list", "tables"}
	response, err := exec.Command("nft", args...).Output()
	if err != nil {
		return nfttables, err
	}

	if !gjson.Valid(string(response)) {
		return nfttables, errors.New("invalid json response")
	}

	tables := gjson.Get(string(response), "nftables.#.table.name")
	if tables.Exists() {
		tables.ForEach(func(key, value gjson.Result) bool {
			nfttables = append(nfttables, value.String())
			return true
		})
	} else {
		return nfttables, errors.New("no tables found")
	}

	return nfttables, nil
}

// get table info for table
func NftGetTableInfo(tablename string) (NFTTABLEDETAILS, error) {
	var tabledetails NFTTABLEDETAILS
	args := []string{"-j", "list", "tables"}
	response, err := exec.Command("nft", args...).Output()
	if err != nil {
		return tabledetails, err
	}

	if !gjson.Valid(string(response)) {
		return tabledetails, errors.New("invalid json response")
	}

	tables := gjson.Get(string(response), "nftables.#(table.name==\""+tablename+"\").table")
	if !tables.Exists() {
		return tabledetails, errors.New("table not found")
	}

	family := gjson.Get(string(response), "nftables.#(table.name==\""+tablename+"\").table.family")
	if !family.Exists() {
		return tabledetails, errors.New("cannot get table family")
	}

	handle := gjson.Get(string(response), "nftables.#(table.name==\""+tablename+"\").table.handle")
	if !handle.Exists() {
		return tabledetails, errors.New("cannot get table handle")
	}

	tabledetails.Family = family.String()
	tabledetails.Table = tablename
	tabledetails.Handle = int(handle.Int())

	return tabledetails, nil
}

func NftListSet(set string) (NFTABLES, error) {
	var nftableData NFTABLES
	args := []string{"-j", "list", "sets"}
	sets, err := exec.Command("nft", args...).Output()
	if err != nil {
		return nftableData, err
	}

	if !gjson.Valid(string(sets)) {
		return nftableData, errors.New("invalid json response")
	}

	version := gjson.Get(string(sets), "nftables.#(@flatten).metainfo.version")
	if !version.Exists() {
		return nftableData, errors.New("invalid json response")
	}

	table := gjson.Get(string(sets), "nftables.#(set.name==\""+set+"\").set.table")
	if !table.Exists() {
		return nftableData, errors.New("cannot find table")
	}

	family := gjson.Get(string(sets), "nftables.#(set.name==\""+set+"\").set.family")
	if !family.Exists() {
		return nftableData, errors.New("cannot find family")
	}

	var elems []string
	elements := gjson.Get(string(sets), "nftables.#(set.name==\""+set+"\").set.elem")
	if elements.Exists() {
		elements.ForEach(func(key, value gjson.Result) bool {
			elems = append(elems, value.String())
			return true
		})
	}

	nftableData = NFTABLES{
		Version:  version.String(),
		Family:   family.String(),
		Table:    table.String(),
		Set:      set,
		Elements: elems,
	}

	return nftableData, nil
}
