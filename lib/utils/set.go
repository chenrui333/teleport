// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package utils

import "maps"

type Set[T comparable] map[T]struct{}

func NewSet[T comparable](elements ...T) Set[T] {
	s := NewSetWithCapacity[T](len(elements))
	s.AddAll(elements)
	return s
}

func NewSetWithCapacity[T comparable](n int) Set[T] {
	return make(map[T]struct{}, n)
}

// Add adds a single element to the set, returning a reference to the updated
// set.
func (s Set[T]) Add(element T) Set[T] {
	s[element] = struct{}{}
	return s
}

func (s Set[T]) AddAll(elements []T) {
	for _, element := range elements {
		s[element] = struct{}{}
	}
}

// Union updates the set to be the union of the original set and `other`
func (s Set[T]) Union(other Set[T]) {
	for element := range other {
		s[element] = struct{}{}
	}
}

func (s Set[T]) Remove(element T) {
	delete(s, element)
}

func (s Set[T]) Contains(element T) bool {
	_, present := s[element]
	return present
}

func (s Set[T]) Clone() Set[T] {
	return maps.Clone(s)
}

// Subtract removes all elements in `other` from the set (i.e `s` becomes the
// Set Difference of `s` and `other`), returning a reference to the mutated set.
func (s Set[T]) Subtract(other Set[T]) Set[T] {
	for k := range other {
		delete(s, k)
	}
	return s
}

// Elements returns the elements in the set. Order of the elements is undefined.
// NOTE: Due to the underlying map type, a set can be naturally ranged over like
// a map, for example:
//
//	alphabet := NewSet("alpha", "beta", "gamma")
//	for l := range alphabet {
//		fmt.Printf("%s is a letter", l)
//	}
//
// Prefer using the natural range iteration where possible
func (s Set[T]) Elements() []T {
	elements := make([]T, 0, len(s))
	for e := range s {
		elements = append(elements, e)
	}
	return elements
}

// // ElementsIter returns an iterator yielding elements of the set. Order of the
// // elements is undefined.
// func (s Set[T]) ElementsIter() iter.Seq[T] {
// 	return func(yield func(T) bool) {
// 		for e := range s {
// 			if !yield(e) {
// 				return
// 			}
// 		}
// 	}
// }
