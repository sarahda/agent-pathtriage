# Replacing the Agent: paper sources

LaTeX sources for the paper. Upload the zip to Overleaf with New Project,
Upload Project. Nothing else needs to be uploaded: `acmart` and
`ACM-Reference-Format.bst` are part of Overleaf's TeX Live.

Set the compiler to pdfLaTeX and the main document to `main.tex`. Both are the
Overleaf defaults.

## Layout

```
main.tex          document class, title, and the list of sections
preamble.tex      packages, colours, and the \todo and \nodata macros
numbers.tex       every number in the paper, with the artifact it came from
refs.bib          bibliography
sections/         one file per section, in reading order
figures/          one file per figure, drawn with TikZ and pgfplots
```

## Two columns now, one column for a journal submission

The first line of `main.tex` selects `sigconf`, which is the two column ACM
layout. ACM journals including TOPS use a single column layout for
submission. To switch, change that one line to:

```latex
\documentclass[acmsmall,nonacm,screen]{acmart}
```

Nothing else changes. `nonacm` removes the copyright block and the conference
footer, which is what an arXiv preprint and a course submission want. Remove
`nonacm` when submitting to ACM so the class puts the rights block back.

## Numbers come from artifacts, not from the text

No number is written in the body of the paper. Each one is a macro defined in
`numbers.tex`, and every definition carries a comment naming the artifact file
it was read from. When an artifact is regenerated, change the macro and the
whole paper follows.

This is deliberate. It is the reason the superseded Foundry count cannot come
back: there is exactly one place that holds it.

If a number has no artifact behind it, do not invent a macro for it. Write
`\nodata` in the text, which prints "not measured".

`evaluation/verify_paper_numbers.py` in the main repository checks this. It
reads every macro back out of `numbers.tex`, recomputes each one from the
artifact it names, and reports any that disagree.

```
python3 evaluation/verify_paper_numbers.py \
    --numbers /path/to/numbers.tex --bench evaluation/benchmark
```

As of the current draft it reports 83 macros, 83 equal, 0 disagreeing, and no
macro without an artifact behind it.

## Drafting markers

`\todo{...}` prints a red marker in the PDF. There are several in this draft,
each one asking for something only you can supply, such as the outcome of a
review or a citation.

Before you submit, set `\draftmode` to 0 in `preamble.tex`. Every remaining
`\todo` then raises a compile error, so no marker can survive into the final
file. `\nodata` is unaffected, because reporting that something was not
measured is a statement and not a gap.

## What is written and what is not

Written from the artifacts: every section, including related work, the
formal treatment and Algorithm 1 in Section 4, the worked example in
Section 5, defences and detection in Section 11, and both appendices.

Every bibliography entry was checked against a primary source: the publisher
page, the conference programme, or the paper's own first page. None is written
from memory.

The five remaining markers need an outcome only you can supply: the pull
request result, the vendor issue, the disclosures, whether the repository is
public, and one last novelty search before submission.

## Building locally

```
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

The current draft is 13 pages in `sigconf` and 20 in `acmsmall`. The 13 is
at the USENIX-style body limit; if you add to it, take the space back from
Sections 1.4, 6.4 or 9, which restate things the results section already
says.
