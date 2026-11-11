"""Minimal stand-in for a curses window: records text into a grid (attributes ignored)."""
import curses


class FakeScreen:
    def __init__(self, rows=40, cols=140):
        self.rows, self.cols = rows, cols
        self.erase()

    def getmaxyx(self):
        return self.rows, self.cols

    def erase(self):
        self.grid = [[" "] * self.cols for _ in range(self.rows)]

    def addstr(self, y, x, s, attr=0):
        if y >= self.rows or x >= self.cols:
            raise curses.error("out of range")
        for i, ch in enumerate(s):
            if x + i >= self.cols:
                raise curses.error("overflow")
            self.grid[y][x + i] = ch

    def refresh(self):
        pass

    def text(self):
        return "\n".join("".join(r).rstrip() for r in self.grid)
