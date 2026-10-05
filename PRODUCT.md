# Product

## Register

product

## Users

Analyste sécurité / développeur (Mattéo Trémisi) et responsable UAT (Fadel Ghamlouche) — LPB Conseil, équipe interne. Usage desktop, poste branché au réseau LPB via overlay ZTNA. Sessions courtes : consultation des scores après une collecte, vérification de l'amélioration après un patch, capture d'écran pour le rapport de stage PFE. Pas d'usage mobile prévu.

## Product Purpose

POC de tableau de bord de scoring de vulnérabilités corrélant iTop (CMDB), Wazuh (SIEM/XDR) et CISO Assistant (GRC). Formule : Score = CVSS × (C + D + I). Objectif opérationnel : prioriser les remédiations par actif. Objectif rapport : produire des captures lisibles et professionnelles pour le jury CESI.

## Brand Personality

Sérieux · Lisible · Professionnel. Outil interne de sécurité, pas un produit commercial. Le soin visuel est au service de la lisibilité des données et de la qualité des captures du rapport — pas de l'esthétique pour elle-même.

## Anti-references

- **PowerPoint exécutif** : gros chiffres sans contexte, palette corporate bleue, look présentation plutôt qu'outil.
- **SaaS startup** : fond clair/sable, card grids identiques, accent violet/bleu, hero-metric template.
- **Grafana / dashboards génériques** : grilles de panneaux interchangeables, couleurs par défaut, densité max sans hiérarchie, aucun soin typographique.

## Design Principles

1. **La donnée prime** : hiérarchie visuelle construite autour de la criticité et du score, pas de la décoration.
2. **Densité maîtrisée** : assez compact pour voir les 3 actifs et leurs CVEs sans scroller, assez aéré pour être lisible en capture d'écran.
3. **Le progrès est visible** : la carte de remédiation vs baseline est le premier élément que l'œil accroche après le titre.
4. **Critique avant tout** : rouge et orange dominent l'espace — l'outil ne minimise pas l'exposition.
5. **Dark-native** : thème sombre SOC assumé, jamais un mode nuit ajouté après coup.

## Accessibility & Inclusion

WCAG AA minimum. Contraste corps ≥ 4.5:1. UI exclusivement en français. Aucune exigence de daltonisme documentée, mais les badges de criticité utilisent à la fois la couleur et le texte.
