
  # IDS 監控儀表板設計

  This is a code bundle for IDS 監控儀表板設計. The original project is available at https://www.figma.com/design/HFcSHTfD2ffLywsTGEW334/IDS-%E7%9B%A3%E6%8E%A7%E5%84%80%E8%A1%A8%E6%9D%BF%E8%A8%AD%E8%A8%88.

  ## Running the code

  Run `npm i` to install the dependencies.

  Start backend API (from `frontend/`):

  `npm run api`

  Start frontend dev server (another terminal):

  `npm run dev`

  Open frontend website directly (no backend, no analysis run):

  `npm run web`

  Notes:
  - The backend API runs `main.py` when you click `執行後端分析`.
  - By default, API run skips privacy-ratio sweep; set `runPrivacySweep=true` in request body to enable it.
  - Model file is required: `logistic_regression_model/output_lr/lr_model.joblib`.
  - Generated charts are loaded from `output_results/privacy_ratio_plots/`.
  