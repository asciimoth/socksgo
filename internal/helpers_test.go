package internal_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/asciimoth/socks/internal"
)

func TestReadNullTerminatedString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		bufSize int
		want    string
		wantErr error
	}{
		{
			name:    "empty string",
			input:   "\x00",
			bufSize: 10,
			want:    "",
		},
		{
			name:    "simple string",
			input:   "hello\x00",
			bufSize: 10,
			want:    "hello",
		},
		{
			name:    "string with null in middle",
			input:   "hello\x00world",
			bufSize: 10,
			want:    "hello",
		},
		{
			name:    "string longer than buffer",
			input:   "abcdefghijklmnop",
			bufSize: 5,
			wantErr: internal.TooLongStringErr,
		},
		{
			name:    "exact buffer size without null",
			input:   "abcd",
			bufSize: 4,
			wantErr: internal.TooLongStringErr,
		},
		{
			name:    "exact buffer size with null at end",
			input:   "abc\x00",
			bufSize: 4,
			want:    "abc",
		},
		{
			name:    "string with special characters",
			input:   "hello\tworld\n\x00",
			bufSize: 20,
			want:    "hello\tworld\n",
		},
		{
			name:    "unicode string",
			input:   "hello 世界\x00",
			bufSize: 20,
			want:    "hello 世界",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader([]byte(tt.input))
			buf := make([]byte, tt.bufSize)

			got, err := internal.ReadNullTerminatedString(r, buf)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("ReadNullTerminatedString() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("ReadNullTerminatedString() unexpected error = %v", err)
				return
			}

			if string(got) != tt.want {
				t.Errorf("ReadNullTerminatedString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadNullTerminatedString_EdgeCases(t *testing.T) {
	t.Run("immediate null", func(t *testing.T) {
		r := bytes.NewReader([]byte{0})
		buf := make([]byte, 10)
		got, err := internal.ReadNullTerminatedString(r, buf)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("single character before null", func(t *testing.T) {
		r := bytes.NewReader([]byte{'a', 0})
		buf := make([]byte, 2)
		got, err := internal.ReadNullTerminatedString(r, buf)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if string(got) != "a" {
			t.Errorf("expected 'a', got %q", got)
		}
	})

	t.Run("buffer size 1", func(t *testing.T) {
		r := bytes.NewReader([]byte{0})
		buf := make([]byte, 1)
		got, err := internal.ReadNullTerminatedString(r, buf)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("reader error mid-stream", func(t *testing.T) {
		// Create a custom reader that returns an error after reading 'a'
		errorReader := &errorReader{
			data: []byte{'a', 'b'},
			err:  io.ErrUnexpectedEOF,
			pos:  1,
		}
		buf := make([]byte, 10)
		_, err := internal.ReadNullTerminatedString(errorReader, buf)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
		}
	})
}

func TestReadNullTerminatedString_IncrementalReads(t *testing.T) {
	t.Run("slow reader with multiple reads", func(t *testing.T) {
		// Simulate a reader that returns 1 byte at a time
		data := []byte("hello\x00")
		slowReader := &slowReader{data: data}
		buf := make([]byte, 10)

		got, err := internal.ReadNullTerminatedString(slowReader, buf)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if string(got) != "hello" {
			t.Errorf("expected 'hello', got %q", got)
		}

		// Verify all bytes were read
		if slowReader.pos != len(data) {
			t.Errorf("expected to read all %d bytes, read %d", len(data), slowReader.pos)
		}
	})
}

// Test helper types

// errorReader returns an error after reading pos bytes
type errorReader struct {
	data []byte
	err  error
	pos  int
	read int
}

func (r *errorReader) Read(p []byte) (int, error) {
	if r.read >= r.pos {
		return 0, r.err
	}
	n := copy(p, r.data[r.read:r.pos])
	r.read += n
	return n, nil
}

// slowReader returns at most 1 byte per Read call
type slowReader struct {
	data []byte
	pos  int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}
