# Accessibility

Tsong should be usable by everyone who runs it, configures it or contributes to it, including people who use a screen reader, a braille display, screen magnification or voice control. Tsong is a server and a command-line tool, so for most people that means its command output, its logs, its config files and its documentation.

## Priorities

- **Plain-text output.** `tsong check` and `tsong serve` print plain text: no color, no cursor movement, no progress animations, no box drawing. Nothing is conveyed by color or layout alone, so output reads the same in a screen reader, a braille display or a log viewer.
- **Errors that say what to do.** An error names the field or input, what was wrong, and the expected form, such as `a duration must be [d.]hh:mm:ss[.fffffff], such as "00:15:00"`, so it can be acted on without seeing anything else.
- **Machine-readable logs.** Audit lines are JSON, one event per line, so any tool can read, filter or speak them.
- **Readable config.** Config and bootstrap files are TOML with plain comment headings, and the samples explain each setting in words.
- **Accessible documentation.** The docs are Markdown in the repository, rendered by GitHub, with a logical heading order, descriptive link text, real lists and tables with headers. A diagram, if one is added, comes with a text description.

Tsong makes no claim of conformance to WCAG or another standard. These priorities are its working goals.

## Contributor expectations

- **Output and errors**
  - Keep command output plain text. Don't add color, spinners or other terminal effects, and never convey meaning by color or position alone.
  - Write error messages that name the input, what was wrong and the expected form.
- **Documentation and samples**
  - Use a logical heading order without skipping levels, and real Markdown lists and tables.
  - Use descriptive link text, never "click here".
  - Describe any image or diagram in text nearby.
  - Use plain comment headings in sample configs, not box-drawing or ASCII-art dividers.
- **Review.** Note any change to how output, errors or docs read in the pull request. No automated accessibility checks run in CI today.

## Reporting accessibility issues

If something in Tsong, its output or its docs is hard or impossible for you to use, please tell us. An accessibility report is expertise, not a complaint.

1. Open an issue with the [accessibility issue form](https://github.com/dzong-labs/tsong/issues/new?template=accessibility.yml).
2. Include, when you can:
   - What you were trying to do, and what got in the way.
   - Where: the command, the error, the file or the doc page.
   - Your operating system, terminal and assistive technology, with versions.
   - A recording or screenshot, only if you're comfortable sharing one.

You never need to describe a disability or share personal information.

### Severity

The maintainer assigns severity during triage; you don't need to.

- **Critical:** you can't complete a core task, such as reading `tsong check`'s result or the setup docs.
- **Serious:** a task is significantly harder, but a workaround exists.
- **Moderate:** an annoyance or an inconsistency.
- **Minor:** little effect on use.

### How we respond

- We reply to every report respectfully and acknowledge the barrier you hit.
- We explain the next steps and any known limitation or dependency involved.
- Where we can, we suggest a workaround while a fix is in progress.
- We post updates on the issue when its status or timeline changes.
- We may ask you to confirm that a fix works before closing the issue.

### Resolution expectations

Targets start when the issue is opened:

- **Critical:** within 30 days.
- **Serious:** within 60 days.
- **Moderate and minor:** within 90 days.

If a target slips, we say why on the issue, share any workaround, and give a new date.

## Ownership and maintenance

The maintainer, Mark Lauter, owns accessibility, as [GOVERNANCE.md](GOVERNANCE.md) describes. That covers triaging reports, tracking known barriers, giving status updates, and keeping this document current.

## Supported environments

- **The `tsong` command:** Linux, in any terminal. Its output is plain text, so it works with terminal screen readers such as Orca, and with NVDA, JAWS or VoiceOver through a terminal emulator.
- **The documentation:** GitHub's web interface, in any browser and with any assistive technology that GitHub supports.

Tsong has no graphical interface or web pages of its own.

## Known limitations

- Prometheus metrics are a machine format, read through a dashboard tool. How accessible they are depends on that tool.

Please open an accessibility issue if you find another barrier.

## Feedback

Suggestions for this document or for Tsong's accessibility practices are welcome as an issue or a pull request. Report an active barrier through the issue form above.
