# Reviewer packet export schema

Run the exporter from the parent assessment directory after a clean root-cause-family leakage audit and both signed pre-access JSON declarations are complete. It creates two reviewer-specific directories under a destination outside the repository. Do not place detector predictions, detector/model configuration, tuning notes, commit/tree/blob/source hashes, patch references, or family IDs in those directories. Each case file contains the exact source bytes plus a minimal scope prompt; parser status is shown as input metadata so a reviewer can record partial/unknown accurately.

Keep reviewer workspaces separate until both signed submissions are frozen. The declaration records whether the reviewer participated in detector work, saw tuning/results, recognized the source/patch, or has other conflicts. Any “yes” to detector work/result exposure invalidates the reviewer for this batch. A “yes” to public patch/source exposure requires replacement or documented exclusion. Never coerce an `unknown` into safe.

