package ui

import (
	"image"
	"image/color"
	"os"
	"testing"
)

func TestRenderHalfblocksBasic(t *testing.T) {
	tests := []struct {
		name  string
		imgW  int
		imgH  int
		cellW int
		cellH int
	}{
		{"square 4x4 to 2x2", 4, 4, 2, 2},
		{"wide 100x50 to 40x12", 100, 50, 40, 12},
		{"narrow 10x20 to 5x5", 10, 20, 5, 5},
		{"1x2 image to 1x1 grid", 1, 2, 1, 1},
		{"exact match 6x4 to 3x2", 6, 4, 3, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := image.NewRGBA(image.Rect(0, 0, tt.imgW, tt.imgH))
			// Fill with a solid color so every pixel is valid.
			for y := 0; y < tt.imgH; y++ {
				for x := 0; x < tt.imgW; x++ {
					img.Set(x, y, color.NRGBA{R: 128, G: 64, B: 32, A: 255})
				}
			}

			cells := renderHalfblocks(img, tt.cellW, tt.cellH)
			want := tt.cellW * tt.cellH
			if len(cells) != want {
				t.Errorf("got %d cells, want %d", len(cells), want)
			}

			for i, c := range cells {
				if c.char != '▀' {
					t.Errorf("cell[%d].char = %q, want '▀'", i, c.char)
				}
			}
		})
	}
}

func TestRenderHalfblocksColors(t *testing.T) {
	// Use a solid green image to verify color fidelity through resize.
	// CatmullRom preserves solid colors exactly (no interpolation needed).
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	green := color.NRGBA{R: 0, G: 200, B: 50, A: 255}
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, green)
		}
	}

	cells := renderHalfblocks(img, 10, 5)
	if len(cells) != 50 {
		t.Fatalf("got %d cells, want 50", len(cells))
	}

	for i, c := range cells {
		fgR, fgG, fgB := c.fg.RGB()
		bgR, bgG, bgB := c.bg.RGB()
		// Solid color: both fg and bg must be green-dominant.
		if fgG <= fgR || fgG <= fgB {
			t.Errorf("cell[%d] fg: r=%d,g=%d,b=%d, expected green-dominant", i, fgR, fgG, fgB)
		}
		if bgG <= bgR || bgG <= bgB {
			t.Errorf("cell[%d] bg: r=%d,g=%d,b=%d, expected green-dominant", i, bgR, bgG, bgB)
		}
	}
}

func TestRenderHalfblocksEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		img   image.Image
		cellW int
		cellH int
		want  int
	}{
		{
			"zero cell dimensions",
			image.NewRGBA(image.Rect(0, 0, 10, 10)),
			0, 0, 0,
		},
		{
			"zero cell width",
			image.NewRGBA(image.Rect(0, 0, 10, 10)),
			0, 5, 0,
		},
		{
			"zero cell height",
			image.NewRGBA(image.Rect(0, 0, 10, 10)),
			5, 0, 0,
		},
		{
			"zero image",
			image.NewRGBA(image.Rect(0, 0, 0, 0)),
			5, 5, 0,
		},
		{
			"1x1 image to 2x2 grid",
			image.NewRGBA(image.Rect(0, 0, 1, 1)),
			2, 2, 4,
		},
		{
			"image smaller than grid",
			image.NewRGBA(image.Rect(0, 0, 2, 2)),
			4, 4, 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cells := renderHalfblocks(tt.img, tt.cellW, tt.cellH)
			if len(cells) != tt.want {
				t.Errorf("got %d cells, want %d", len(cells), tt.want)
			}
		})
	}
}

func TestRenderHalfblocksUpscale(t *testing.T) {
	// A single-pixel-wide vertical stripe image: column 0 white, rest black.
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	white := color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	black := color.NRGBA{R: 0, G: 0, B: 0, A: 255}
	for y := 0; y < 4; y++ {
		img.Set(0, y, white)
		for x := 1; x < 4; x++ {
			img.Set(x, y, black)
		}
	}

	// Upscale to 8x4 grid. CatmullRom should interpolate smoothly,
	// but the key invariant is: every cell is populated with valid colors.
	cells := renderHalfblocks(img, 8, 4)
	want := 8 * 4
	if len(cells) != want {
		t.Fatalf("got %d cells, want %d", len(cells), want)
	}

	// First column cells should have high-brightness foreground.
	c := cells[0]
	r, g, b := c.fg.RGB()
	if r == 0 && g == 0 && b == 0 {
		t.Errorf("first cell fg is black, expected white from column 0")
	}
}

func TestEnsureTrueColor(t *testing.T) {
	tests := []struct {
		name      string
		preset    string
		wantSet   bool
		wantValue string
	}{
		{
			"unset gets truecolor",
			"",
			true,
			"truecolor",
		},
		{
			"existing value preserved",
			"24bit",
			true,
			"24bit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig, wasSet := os.LookupEnv("COLORTERM")
			t.Cleanup(func() {
				if wasSet {
					_ = os.Setenv("COLORTERM", orig)
				} else {
					_ = os.Unsetenv("COLORTERM")
				}
			})

			_ = os.Setenv("COLORTERM", tt.preset)
			ensureTrueColor()

			got := os.Getenv("COLORTERM")
			if got != tt.wantValue {
				t.Errorf("COLORTERM = %q, want %q", got, tt.wantValue)
			}
		})
	}
}
