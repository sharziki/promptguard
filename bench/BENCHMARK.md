# PromptGuard benchmark

**Date:** 2026-09-17
**Detector:** TypeSafe AI Jev (System One), single typed call
**Data:** two independent public datasets, unmodified

## Results

| Dataset | n | Attack rate | AUC | 95% CI | Avg precision |
|---|---|---|---|---|---|
| `deepset/prompt-injections` | 300 | 18.0% | **0.988** | [0.978, 0.996] | 0.948 |
| `jackhhao/jailbreak-classification` | 300 | 45.7% | **0.981** | [0.964, 0.994] | 0.982 |

600 calls, **zero errors**. Median latency 155-177ms. Cost $18.90-$27.49 per
million scans.

## The separation is what matters

| | Attack inputs | Benign inputs |
|---|---|---|
| median score | 0.98 | 0.02-0.03 |
| 95th percentile | 0.99 | 0.04-0.10 |
| **maximum benign score** | - | **0.20** |

Across 300 benign inputs, nothing scored above 0.20. That gap is what makes a
near-zero-false-alarm threshold possible.

## Operating points

Thresholds are set by **false-alarm budget**, not recall target, and must hold on
*both* datasets. A filter that blocks 10% of real users gets switched off.

| Level | Block at | jailbreak recall | jailbreak FA | injections recall | injections FA |
|---|---|---|---|---|---|
| `balanced` | 0.134 | 93.4% | 1.2% | 70.4% | **0.0%** |
| `strict` | 0.099 | 93.4% | 5.5% | 75.9% | **0.0%** |
| `paranoid` | 0.05 | 97.8% | 30.1% | 88.9% | 3.3% |

Counting the FLAG band as "caught", balanced catches 93.4% / 75.9%.

### A methodology correction worth recording

The first version of `derive_thresholds.py` pooled both datasets' attack-score
distributions and picked thresholds by recall quantile. That produced
**10-70% false-alarm rates**, because the two corpora have different score
distributions and the pooled quantile was dominated by whichever corpus had more
low-scoring attacks. Selecting by false-alarm budget instead fixed it. The bad
version is described here rather than quietly deleted, because "optimize the
constraint that actually binds" is the transferable lesson.

## Limitations

1. **This is one layer, not a security boundary.** It inspects text. It cannot
   stop an attack that never reaches it, and it must not replace authorization.
2. **`deepset` recall is 70% at the default.** Roughly three in ten of its
   attacks score low enough to pass. Use `paranoid` where a miss is costlier than
   a false alarm, and layer other defenses regardless.
3. **Not adversarially tested.** These are public benchmark corpora. An attacker
   who knows this filter exists can probe it. Real deployment needs monitoring of
   the FLAG band.
4. **English only.** Multilingual injection is untested.
5. **Two datasets.** Consistent across both, which is real evidence, but not proof
   it holds on your traffic. Recalibrate with `bench/derive_thresholds.py`.

## Reproduce

```bash
cd ~/jev-judge-bench
source ~/.config/typesafe/credentials.env
python run_injection.py --dataset deepset/prompt-injections --n 300
python run_injection.py --dataset jackhhao/jailbreak-classification --n 300

cd ~/promptguard
python bench/derive_thresholds.py     # regenerate the threshold table
python -m pytest                      # 20 tests incl. live real-attack suite
```
