## Online-Kompilierung

Dieses Projekt enthält `.github/workflows/build.yml`. Nach dem Hochladen auf GitHub:

1. Repository öffnen → **Actions**
2. Workflow **Build roothide tweak** auswählen
3. **Run workflow** drücken
4. Nach dem Lauf unter **Artifacts** die `.deb` herunterladen

Der Workflow verwendet einen macOS-14-GitHub-Runner, roothide/Theos und das iPhoneOS-16.5-SDK. Der Runner wird von GitHub bereitgestellt; ein eigener Mac ist dafür nicht erforderlich.

GitHub Actions kann bei neuen Accounts/privaten Repositories Limits oder eine Zahlungsmethode verlangen. Für öffentliche Repositories sind die verfügbaren Minuten abhängig von GitHub-Richtlinien.
