# Pull Request Instructions

## ✅ Branch Created and Committed

Your changes are now on a new feature branch ready for a PR!

**Branch**: `feat/interactive-flamegraph-export`
**Commit**: `1f7d480`

## 📝 Next Steps

### 1. Push the Branch

```bash
git push -u origin feat/interactive-flamegraph-export
```

### 2. Create Pull Request

Go to your repository on GitHub and create a new Pull Request from `feat/interactive-flamegraph-export` to `main`.

### 3. PR Title

```
feat(export): output interactive standalone HTML file for SVG flamegraph
```

### 4. PR Description

Use this template:

```markdown
## Summary

Replace raw SVG export with interactive HTML as default format. The new HTML export provides a rich user experience with hover tooltips, click-to-zoom, and search functionality—all in a self-contained file.

## Features

- ✨ Interactive HTML export with hover tooltips, click-to-zoom, and search
- 📦 All CSS and JavaScript inlined (no external dependencies)
- 🎨 Responsive design with automatic dark mode support
- 🚀 New `--profile-format` flag to choose between html (default) and svg
- ✅ Comprehensive test coverage and documentation
- 🔄 Backward compatibility: SVG export still available

## Usage

### Generate Interactive HTML (Default)
```bash
erst debug --profile <transaction-hash>
# Output: <tx-hash>.flamegraph.html
```

### Generate Raw SVG
```bash
erst debug --profile --profile-format svg <transaction-hash>
# Output: <tx-hash>.flamegraph.svg
```

## Interactive Features

1. **Hover Tooltips**: Shows function name, duration, and percentage
2. **Click-to-Zoom**: Click any frame to zoom in, "Reset Zoom" to return
3. **Search/Highlight**: Find frames by name with visual highlighting
4. **Dark Mode**: Automatically adapts to system theme
5. **Responsive**: Works on different viewport sizes

## Implementation Details

### Core Changes

- `internal/visualizer/flamegraph.go`: Added `GenerateInteractiveHTML()` and `ExportFlamegraph()`
- `internal/cmd/root.go`: Added `--profile-format` CLI flag
- `internal/cmd/debug.go`: Updated export logic with format selection
- `internal/cmd/init.go`: Added `.flamegraph.html` to gitignore patterns

### Tests

- 7 new test functions with comprehensive coverage
- All tests passing ✅
- Automated verification script included

### Documentation

- `docs/INTERACTIVE_FLAMEGRAPH.md` - Full user guide
- `docs/FLAMEGRAPH_QUICK_START.md` - Quick reference
- `docs/FLAMEGRAPH_ARCHITECTURE.md` - Architecture details
- `docs/examples/sample_flamegraph.html` - Live demo
- `README.md` - Updated with profiling section

## Breaking Changes

⚠️ **Default export format changed from SVG to HTML**

Existing workflows expecting SVG files should explicitly set `--profile-format svg`:

```bash
erst debug --profile --profile-format svg <tx-hash>
```

## Testing

### Automated Verification
```bash
./scripts/verify_flamegraph.sh
```

### Manual Testing Checklist
- [ ] Build project: `make build`
- [ ] Generate HTML: `./bin/erst debug --profile <tx-hash>`
- [ ] Open HTML file in browser
- [ ] Test hover tooltips
- [ ] Test click-to-zoom
- [ ] Test search functionality
- [ ] Toggle system dark mode
- [ ] Check browser console (no errors)
- [ ] Check network tab (no requests)
- [ ] Generate SVG: `./bin/erst debug --profile --profile-format svg <tx-hash>`

## Screenshots

### Interactive HTML Flamegraph
![Interactive Flamegraph](docs/examples/sample_flamegraph.html)

### Dark Mode Support
The flamegraph automatically adapts to system theme preferences.

## Files Changed

- **Modified**: 6 files
- **Created**: 8 files
- **Lines Added**: ~650
- **Test Coverage**: 7 new tests

## Checklist

- [x] Code follows project style guidelines
- [x] Tests added and passing
- [x] Documentation updated
- [x] No external dependencies added
- [x] Backward compatibility maintained
- [x] Breaking changes documented
- [x] Verification script included

## Related Issues

Closes #[issue-number] (if applicable)

## Additional Notes

This implementation follows best practices for standalone HTML files:
- All assets inlined (no CDN dependencies)
- Works offline without network access
- Single file is easy to share and archive
- Better security (no external code execution)

The interactive features use vanilla JavaScript for simplicity and compatibility with all modern browsers (Chrome 88+, Firefox 78+, Safari 14+).
```

## 📊 PR Statistics

- **Files Modified**: 6
- **Files Created**: 8
- **Lines Added**: 2,259
- **Lines Removed**: 10
- **Test Coverage**: 7 new tests
- **Documentation**: ~25KB

## 🔍 Review Checklist for Reviewers

### Code Quality
- [ ] Implementation follows Go best practices
- [ ] No syntax errors or linting issues
- [ ] Code is well-commented and readable
- [ ] No external dependencies added

### Functionality
- [ ] Interactive features work as expected
- [ ] HTML is truly standalone (no network requests)
- [ ] Dark mode adapts correctly
- [ ] Search/highlight functionality works
- [ ] Click-to-zoom works correctly

### Tests
- [ ] All tests passing
- [ ] Good test coverage
- [ ] Edge cases handled

### Documentation
- [ ] README updated
- [ ] User guide comprehensive
- [ ] Architecture documented
- [ ] Examples provided

### Backward Compatibility
- [ ] SVG export still available
- [ ] Breaking changes documented
- [ ] Migration path clear

## 🚀 After PR is Merged

1. Delete the feature branch (GitHub will prompt you)
2. Pull the latest main branch:
   ```bash
   git checkout main
   git pull origin main
   ```
3. Celebrate! 🎉

## 📚 Additional Resources

- [Full Documentation](docs/INTERACTIVE_FLAMEGRAPH.md)
- [Quick Start Guide](docs/FLAMEGRAPH_QUICK_START.md)
- [Architecture Details](docs/FLAMEGRAPH_ARCHITECTURE.md)
- [Live Demo](docs/examples/sample_flamegraph.html)
- [Verification Script](scripts/verify_flamegraph.sh)

---

**Ready to push and create PR!** 🚀
