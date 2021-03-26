# Contributing

This project welcomes contributions and suggestions.
Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution.
For details, visit https://cla.opensource.microsoft.com.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/).
Contact [opencode@microsoft.com](mailto:opencode@microsoft.com) for any additional questions or comments.

### Pull Requests

Submit pull requrests to **branch *contrib***.
Pull requests to any other branch will not be accepted.

When you submit a pull request, a CLA bot will automatically determine whether you need to **provide a CLA** and decorate the PR appropriately (e.g., status check, comment).
Simply follow the instructions provided by the bot. You will only need to do this once across all repos using our CLA.

### Formatting

APSI uses a customized `.clang-format` configuration for C++ code styling.
A script `tools/scripts/clang-format-all.sh` is provided to easily format all C++ sources and headers.
To ensure the code is properly formatted before making a pull request, we highly recommend using [pre-commit](https://pre-commit.com/).
Note that the repository includes a `.pre-commit-config.yaml` that describes the appropriate formatting checks.

Documentation are mostly written in GitHub-flavored Markdown.
A line break is required after each full sentence.
