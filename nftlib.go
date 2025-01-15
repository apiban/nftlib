// NFTLIB - exec commands to work with NFTABLES
// Copyright (C) 2025 Fred Posner
// Copyright (C) 2025 The Palner Group, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

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

// nft list add element to set
func NftAddSetElement(data NFTABLES, ipaddress string) error {
	args := []string{"add", "element", data.Family, data.Table, data.Set, "{", ipaddress, "}"}
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

	//nftables.#(set=="set").set.elem
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
