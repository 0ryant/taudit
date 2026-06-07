# arXiv submission preflight

Date: 2026-06-01
Status: preflight checklist; not a submission receipt

## Submission package gates

- Registered arXiv author is available for self-submission.
- Selected category is justified, likely `cs.SE` with `cs.CR` cross-list only
  if the final paper supports the security contribution.
- Endorsement status is checked for the submitting author and category.
- Paper is a refereeable research contribution, not product launch copy.
- TeX/LaTeX source bundle is prepared; do not upload a PDF generated from TeX
  source as the primary submission.
- File names use only arXiv-portable characters:
  `a-z A-Z 0-9 _ + - . , =`.
- Figure file names and LaTeX references match case exactly.
- All figures referenced by the paper are included.
- Bibliography artifacts are included as `.bib` and/or generated `.bbl`
  according to the chosen build flow.
- Ancillary data/code is either uploaded as ancillary material or linked to a
  stable public artifact with versioned commit/checksum.
- Generative-AI assistance is disclosed if the final venue/category norms or
  author policy require it.

## Scientific gates

- Benchmark corpus commit and workflow digests are pinned.
- taudit source commit, binary checksum, and `taudit --version` are recorded.
- Raw outputs, normalized detections, timing CSV, and summary JSON are retained.
- Taxonomy mapping includes out-of-scope rows and author-review notes.
- Detection volume is not described as precision or recall.
- FP/FN claims are absent unless the labeling protocol has been executed.
- Validity threats describe parser partiality, taxonomy judgment, lack of
  ground truth, hardware/runtime differences, and source-local execution.

## Official guidance checked

- <https://info.arxiv.org/help/submit/index.html>
- <https://info.arxiv.org/help/submit_tex.html>
- <https://info.arxiv.org/help/submit_pdf.html>
- <https://info.arxiv.org/help/moderation/index.html>

## Stop condition

If the artifact mainly says "taudit exists" or "taudit is better", do not submit
to arXiv. Publish a repository research note and keep the claim ceiling at
source-local evidence.
