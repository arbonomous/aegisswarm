"""End-to-end UI & workflow verification for the unified AegisSwarm macOS app."""

from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch


def _make_fake_appkit():
    appkit = types.ModuleType("AppKit")
    foundation = types.ModuleType("Foundation")
    objc_mod = types.ModuleType("objc")

    class _FakeView:
        def __init__(self, frame=(0, 0, 100, 30)):
            self._frame = frame
            self._hidden = False
            self._title = ""
            self._string = ""
            self._subviews = []
            self._enabled = True
            self._selected = 0

        def setFrame_(self, rect):
            self._frame = rect

        def setFrameOrigin_(self, pt):
            self._frame = (pt[0], pt[1], self._frame[2], self._frame[3])

        def frame(self):
            class _Origin:
                def __init__(self, x, y):
                    self.x, self.y = x, y
            class _Size:
                def __init__(self, w, h):
                    self.width, self.height = w, h
            class _Rect:
                def __init__(self, f):
                    self.origin = _Origin(f[0], f[1])
                    self.size = _Size(f[2], f[3])
            return _Rect(self._frame)

        def setHidden_(self, val):
            self._hidden = bool(val)

        def isHidden(self):
            return self._hidden

        def setTitle_(self, t):
            self._title = t

        def title(self):
            return self._title

        def setString_(self, s):
            self._string = str(s)

        def setStringValue_(self, s):
            self._string = str(s)

        def string(self):
            return self._string

        def stringValue(self):
            return self._string

        def addSubview_(self, v):
            self._subviews.append(v)

        def subviews(self):
            return self._subviews

        def setEnabled_(self, val):
            self._enabled = bool(val)

        def __getattr__(self, _name):
            return lambda *a, **kw: None

    class _FakeAlloc(_FakeView):
        @classmethod
        def alloc(cls):
            return cls()

        def init(self):
            return self

        def initWithFrame_(self, rect):
            return _FakeAlloc(rect)

        def initWithFrame_pullsDown_(self, rect, _pd):
            v = _FakeAlloc(rect)
            v._items = []
            return v

        def initWithContentRect_styleMask_backing_defer_(self, rect, *_a):
            p = _FakeAlloc(rect)
            p._content = _FakeView(rect)
            return p

        def contentView(self):
            return self._content

        def addItemsWithTitles_(self, titles):
            self._items = list(titles)
            self._selected = 0

        def selectItemWithTitle_(self, title):
            if title in self._items:
                self._selected = self._items.index(title)

        def titleOfSelectedItem(self):
            return self._items[self._selected] if self._items else "Overview"

        def setSelectedSegment_(self, idx):
            self._selected = int(idx)

        def selectedSegment(self):
            return self._selected

        def textContainer(self):
            return _FakeView()

        @classmethod
        def labelWithString_(cls, s):
            v = cls()
            v._string = str(s)
            return v

        @classmethod
        def appearanceNamed_(cls, _name):
            return cls()

        @classmethod
        def colorWithRed_green_blue_alpha_(cls, *_a):
            return cls()

        @classmethod
        def boldSystemFontOfSize_(cls, _s):
            return cls()

        @classmethod
        def systemFontOfSize_(cls, _s):
            return cls()

        def initWithContentsOfFile_(self, _p):
            return self

    for name in (
        "NSPanel", "NSBackingStoreBuffered", "NSWindowStyleMaskTitled",
        "NSWindowStyleMaskClosable", "NSFloatingWindowLevel", "NSTextField",
        "NSTextView", "NSScrollView", "NSButton", "NSOpenPanel", "NSSavePanel",
        "NSAlert", "NSModalResponseOK", "NSAlertFirstButtonReturn",
        "NSPopUpButton", "NSImageView", "NSImage", "NSSound", "NSPasteboard",
        "NSPasteboardTypeString", "NSColor", "NSBox", "NSFont", "NSAppearance",
        "NSSegmentedControl",
    ):
        if "Mask" in name or "Buffered" in name or "Level" in name or "OK" in name or "Return" in name or "Type" in name:
            setattr(appkit, name, 1)
        else:
            setattr(appkit, name, _FakeAlloc)

    appkit.NSMakeRect = lambda x, y, w, h: (x, y, w, h)
    appkit.NSMakeSize = lambda w, h: (w, h)

    class _NSObject:
        @classmethod
        def alloc(cls):
            return cls()

        def init(self):
            return self

    foundation.NSObject = _NSObject
    objc_mod.super = super
    objc_mod.python_method = lambda fn: fn
    return appkit, foundation, objc_mod


class AppEndToEndTests(unittest.TestCase):
    def test_unified_3_tab_app_lifecycle_and_actions(self):
        import native_workspace

        appkit, foundation, objc_mod = _make_fake_appkit()
        with patch.dict(
            sys.modules,
            {"AppKit": appkit, "Foundation": foundation, "objc": objc_mod},
        ):
            ctrl = native_workspace._build()

            # 1. Starts cleanly on Overview (Home tab), technical chrome hidden
            self.assertEqual(ctrl.mode, "Overview")
            self.assertEqual(ctrl.tabs.selectedSegment(), 0)
            self.assertTrue(ctrl.sections.isHidden())
            self.assertTrue(ctrl.copy_button.isHidden())
            self.assertTrue(ctrl.details_button.isHidden())
            self.assertTrue(all(v.isHidden() for v in ctrl.metric_cards))
            self.assertFalse(ctrl.clean_button.isHidden())
            self.assertFalse(ctrl.test_block_button.isHidden())
            self.assertIn("LIVE PROTECTION", ctrl.results.string())

            # 2. Switch to Health tab -> metric cards appear, buttons move below cards (no overlap)
            ctrl.tabs.setSelectedSegment_(1)
            ctrl.tabChanged_(None)
            self.assertEqual(ctrl.mode, "Mac Health & Cleanup")
            self.assertFalse(any(v.isHidden() for v in ctrl.metric_cards))
            self.assertEqual(ctrl.clean_button._frame[1], 400)
            self.assertEqual(ctrl.scroll._frame[3], 336)
            self.assertIn("YOUR MAC'S HEALTH", ctrl.results.string())
            self.assertTrue(ctrl.cpu_val.string().endswith("%"))
            self.assertTrue(ctrl.ram_val.string().endswith("%"))
            self.assertTrue(ctrl.disk_val.string().endswith("%"))

            # 3. Switch to Activity tab -> metric cards hide, scroll expands
            ctrl.tabs.setSelectedSegment_(2)
            ctrl.tabChanged_(None)
            self.assertEqual(ctrl.mode, "Activity")
            self.assertTrue(all(v.isHidden() for v in ctrl.metric_cards))
            self.assertEqual(ctrl.clean_button._frame[1], 488)
            self.assertEqual(ctrl.scroll._frame[3], 424)

            # 4. Toggle protection from main window button
            with patch("menubar.toggle_live_guardian", return_value="Started"), patch(
                "menubar.guardian_running", return_value=True
            ):
                ctrl.tabs.setSelectedSegment_(0)
                ctrl.tabChanged_(None)
                ctrl.toggleProtectionClicked_(None)
                self.assertEqual(ctrl.home_button.title(), "Pause Protection")
                self.assertIn("Live Protection Active", ctrl.headline.string())

            # 5. Clean Up Mac & Check for Threats work end-to-end without TypeError
            captured_ops = []
            with patch.object(
                ctrl, "startWorker_", side_effect=lambda op, kind="workspace": captured_ops.append(op())
            ):
                ctrl.cleanMacClicked_(None)
                ctrl.guardClicked_(None)

            self.assertEqual(len(captured_ops), 2)
            cleanup_msg, _ = captured_ops[0]
            self.assertIn("Mac", cleanup_msg)
            self.assertIn("Processor (CPU):", cleanup_msg)
            threat_msg, _ = captured_ops[1]
            self.assertIn("Threat Check Passed", threat_msg)
            self.assertIn("Detect -> Freeze" if "Detect -> Freeze" in threat_msg else "froze it in place", threat_msg)


if __name__ == "__main__":
    unittest.main()
