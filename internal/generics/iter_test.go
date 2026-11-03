// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package generics_test

import (
	"fmt"
	"iter"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/generics"
)

// ExampleErrorIter demonstrates building an [iter.Seq2][T, error] from a
// producer that signals termination by returning an error, without having to
// yield a zero value on every error path.
func ExampleErrorIter() {
	parseNums := func(lines []string) iter.Seq2[int, error] {
		return generics.ErrorIter(func(yield func(int) bool) error {
			for i, line := range lines {
				n, err := strconv.Atoi(line)
				if err != nil {
					return fmt.Errorf("line %d: %w", i, err)
				}
				if !yield(n) {
					return nil
				}
			}
			return nil
		})
	}

	for n, err := range parseNums([]string{"1", "2", "oops", "4"}) {
		if err != nil {
			fmt.Println("error:", err)
			break
		}
		fmt.Println(n)
	}
	// Output:
	// 1
	// 2
	// error: line 2: strconv.Atoi: parsing "oops": invalid syntax
}

func TestErrorIter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		produce  func(yield func(int) bool) error
		wantVals []int
		wantErr  error
	}{
		{
			"AllSuccess",
			func(yield func(int) bool) error {
				for _, v := range []int{1, 2, 3} {
					if !yield(v) {
						return nil
					}
				}
				return nil
			},
			[]int{1, 2, 3},
			nil,
		},
		{
			"Empty",
			func(_ func(int) bool) error {
				return nil
			},
			nil,
			nil,
		},
		{
			"OnlyError",
			func(_ func(int) bool) error {
				return errSentinel
			},
			nil,
			errSentinel,
		},
		{
			"ValuesThenError",
			func(yield func(int) bool) error {
				for _, v := range []int{1, 2} {
					if !yield(v) {
						return nil
					}
				}
				return errSentinel
			},
			[]int{1, 2},
			errSentinel,
		},
		{
			"SingleValue",
			func(yield func(int) bool) error {
				yield(42)
				return nil
			},
			[]int{42},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq := generics.ErrorIter(tc.produce)

			// Iterate twice to verify reusability.
			for range 2 {
				got, err := generics.CollectErrorSeq(seq)
				assert.Equal(t, tc.wantVals, got)
				assert.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}

func TestErrorIter_ZeroValueOnError(t *testing.T) {
	seq := generics.ErrorIter(func(yield func(int) bool) error {
		yield(42)
		return errSentinel
	})

	var pairs []intOrError
	for v, err := range seq {
		pairs = append(pairs, intOrError{v: v, err: err})
	}

	require.Len(t, pairs, 2)
	assert.Equal(t, 42, pairs[0].v)
	assert.NoError(t, pairs[0].err) //nolint:testifylint // we are checking error values directly
	assert.Zero(t, pairs[1].v, "value yielded alongside error should be the zero value")
	assert.ErrorIs(t, pairs[1].err, errSentinel)
}

func TestErrorIter_EarlyTermination(t *testing.T) {
	var produced int
	seq := generics.ErrorIter(func(yield func(int) bool) error {
		for _, v := range []int{1, 2, 3, 4, 5} {
			produced++
			if !yield(v) {
				return nil
			}
		}
		return nil
	})

	for _, err := range seq {
		require.NoError(t, err)
		break
	}
	assert.Equal(t, 1, produced, "producer should stop after consumer breaks")
}

// ExampleReverseIter demonstrates iterating over a slice from last to first
// element.
func ExampleReverseIter() {
	for v := range generics.ReverseIter([]string{"a", "b", "c"}) {
		fmt.Println(v)
	}
	// Output:
	// c
	// b
	// a
}

func TestReverseIter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []int
		want  []int
	}{
		{"Nil", nil, nil},
		{"Empty", []int{}, nil},
		{"Single", []int{42}, []int{42}},
		{"Pair", []int{1, 2}, []int{2, 1}},
		{"Multiple", []int{1, 2, 3, 4, 5}, []int{5, 4, 3, 2, 1}},
		{"Duplicates", []int{1, 2, 1, 2, 1}, []int{1, 2, 1, 2, 1}},
		{"Palindrome", []int{1, 2, 3, 2, 1}, []int{1, 2, 3, 2, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq := generics.ReverseIter(tc.input)

			// Iterate twice to verify reusability.
			assert.Equal(t, tc.want, slices.Collect(seq))
			assert.Equal(t, tc.want, slices.Collect(seq))
		})
	}
}

func TestReverseIter_EarlyTermination(t *testing.T) {
	var got []int
	for v := range generics.ReverseIter([]int{1, 2, 3, 4, 5}) {
		got = append(got, v)
		if v == 3 {
			break
		}
	}
	assert.Equal(t, []int{5, 4, 3}, got, "iteration should stop after the consumer breaks")
}

func TestReverseIter_NamedSliceType(t *testing.T) {
	// Verify the ~[]T constraint accepts named slice types.
	type intSlice []int
	got := slices.Collect(generics.ReverseIter(intSlice{1, 2, 3}))
	assert.Equal(t, []int{3, 2, 1}, got)
}

// ExampleSeqLeft demonstrates extracting only the left values from an
// [iter.Seq2] — here, the indices from [slices.All].
func ExampleSeqLeft() {
	for i := range generics.SeqLeft(slices.All([]string{"a", "b", "c"})) {
		fmt.Println(i)
	}
	// Output:
	// 0
	// 1
	// 2
}

func TestSeqLeft(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input iter.Seq2[int, error]
		want  []int
	}{
		{
			"Empty",
			intErrorSeq2(),
			nil,
		},
		{
			"Single",
			intErrorSeq2(intOrError{v: 42}),
			[]int{42},
		},
		{
			"Multiple",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{v: 2},
				intOrError{v: 3},
			),
			[]int{1, 2, 3},
		},
		{
			"IgnoresRight",
			intErrorSeq2(
				intOrError{v: 1, err: errSentinel},
				intOrError{v: 2},
				intOrError{v: 3, err: errSentinel},
			),
			[]int{1, 2, 3},
		},
		{
			"Duplicates",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{v: 1},
				intOrError{v: 2},
			),
			[]int{1, 1, 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq := generics.SeqLeft(tc.input)

			// Iterate twice to verify reusability.
			assert.Equal(t, tc.want, slices.Collect(seq))
			assert.Equal(t, tc.want, slices.Collect(seq))
		})
	}
}

func TestSeqLeft_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq2(intErrorSeq2(
		intOrError{v: 1},
		intOrError{v: 2},
		intOrError{v: 3},
		intOrError{v: 4},
		intOrError{v: 5},
	), &yielded)

	var got []int
	for v := range generics.SeqLeft(src) {
		got = append(got, v)
		if v == 3 {
			break
		}
	}
	assert.Equal(t, []int{1, 2, 3}, got, "iteration should stop after the consumer breaks")
	assert.Equal(t, 3, yielded, "source should stop after the consumer breaks")
}

// ExampleSeqRight demonstrates extracting only the right values from an
// [iter.Seq2] — here, the values from [slices.All].
func ExampleSeqRight() {
	for v := range generics.SeqRight(slices.All([]string{"a", "b", "c"})) {
		fmt.Println(v)
	}
	// Output:
	// a
	// b
	// c
}

func TestSeqRight(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input iter.Seq2[int, error]
		want  []error
	}{
		{
			"Empty",
			intErrorSeq2(),
			nil,
		},
		{
			"SingleNil",
			intErrorSeq2(intOrError{v: 42}),
			[]error{nil},
		},
		{
			"SingleError",
			intErrorSeq2(intOrError{err: errSentinel}),
			[]error{errSentinel},
		},
		{
			"AllNil",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{v: 2},
				intOrError{v: 3},
			),
			[]error{nil, nil, nil},
		},
		{
			"IgnoresLeft",
			intErrorSeq2(
				intOrError{v: 1, err: errSentinel},
				intOrError{v: 99, err: errSentinel},
			),
			[]error{errSentinel, errSentinel},
		},
		{
			"Mixed",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{err: errSentinel},
				intOrError{v: 3},
			),
			[]error{nil, errSentinel, nil},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq := generics.SeqRight(tc.input)

			// Iterate twice to verify reusability.
			assert.Equal(t, tc.want, slices.Collect(seq))
			assert.Equal(t, tc.want, slices.Collect(seq))
		})
	}
}

func TestSeqRight_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq2(intErrorSeq2(
		intOrError{v: 1},
		intOrError{v: 2},
		intOrError{v: 3},
		intOrError{v: 4},
		intOrError{v: 5},
	), &yielded)

	var count int
	for err := range generics.SeqRight(src) {
		require.NoError(t, err)
		count++
		if count == 3 {
			break
		}
	}
	assert.Equal(t, 3, count, "iteration should stop after the consumer breaks")
	assert.Equal(t, 3, yielded, "source should stop after the consumer breaks")
}

func TestChained_ErrorIter_CollectErrorSeq(t *testing.T) {
	// Parse a set of strings as ints, terminating iteration as soon as one
	// fails to parse.
	parseNums := func(lines []string) iter.Seq2[int, error] {
		return generics.ErrorIter(func(yield func(int) bool) error {
			for i, line := range lines {
				n, err := strconv.Atoi(line)
				if err != nil {
					return fmt.Errorf("line %d: %w", i, err)
				}
				if !yield(n) {
					return nil
				}
			}
			return nil
		})
	}

	got, err := generics.CollectErrorSeq(parseNums([]string{"1", "2", "3"}))
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, got)

	got, err = generics.CollectErrorSeq(parseNums([]string{"1", "2", "nope", "4"}))
	require.Error(t, err)
	assert.Equal(t, []int{1, 2}, got)
}
