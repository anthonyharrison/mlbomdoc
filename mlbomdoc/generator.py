# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.data.document import SBOMDocument
from sbom2doc.docbuilder.consolebuilder import ConsoleBuilder
from sbom2doc.docbuilder.jsonbuilder import JSONBuilder
from sbom2doc.docbuilder.markdownbuilder import MarkdownBuilder
from sbom2doc.docbuilder.pdfbuilder import PDFBuilder


def generate_document(format, sbom_parser, filename, outfile):
    # Get constituent components of the SBOM
    packages = sbom_parser.get_packages()
    document = SBOMDocument()
    document.copy_document(sbom_parser.get_document())

    # Select document builder based on format
    if format == "markdown":
        sbom_document = MarkdownBuilder()
    elif format == "json":
        sbom_document = JSONBuilder()
    elif format == "pdf":
        sbom_document = PDFBuilder()
    else:
        sbom_document = ConsoleBuilder()

    sbom_document.heading(1, "MLBOM Summary")
    sbom_document.createtable(["Item", "Details"], [20, 35])
    sbom_document.addrow(["MLBOM File", filename])
    sbom_document.addrow(["MLBOM Type", document.get_type()])
    sbom_document.addrow(["Version", document.get_version()])
    sbom_document.addrow(["Name", document.get_name()])
    creator = document.get_creator()
    # If creator is missing, will return None
    if creator is not None:
        for c in creator:
            sbom_document.addrow(["Creator", f"{c[0]}:{c[1]}"])
    sbom_document.addrow(["Created", document.get_created()])
    sbom_document.showtable(widths=[5, 9])

    if len(packages) > 0:
        # Detail of each ML model
        sbom_document.paragraph("")
        for package in packages:
            if package["type"] == "MACHINE-LEARNING-MODEL":
                sbom_document.heading(1, f"Model Details - {package.get('name', None)}")

                sbom_document.createtable(["Item", "Value"], [20, 35])
                sbom_document.addrow(["Version", document.get_version()])
                sbom_document.addrow(["Supplier", package.get("supplier", None)])
                sbom_document.addrow(
                    ["License", package.get("licenseconcluded", "NOT KNOWN")]
                )
                sbom_document.showtable(widths=[5, 9])

                if package.get("modelCard") is not None:
                    modelCard = package["modelCard"]
                    # Model Parameters
                    sbom_document.createtable(["Parameter", "Value"], [20, 35])
                    title = False
                    if "learning_type" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Model Parameters")
                            title = True
                        sbom_document.addrow(["Approach", modelCard["learning_type"]])
                    if "task" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Model Parameters")
                            title = True
                        sbom_document.addrow(["Task", modelCard["task"]])
                    if "architecture" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Model Parameters")
                            title = True
                        sbom_document.addrow(
                            ["Architecture Family", modelCard["architecture"]]
                        )
                    if "model" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Model Parameters")
                            title = True
                        sbom_document.addrow(["Model Architecture", modelCard["model"]])
                    if "inputs" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Model Parameters")
                            title = True
                        for input in modelCard["inputs"]:
                            sbom_document.addrow(["Input", input])
                    if "outputs" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Model Parameters")
                            title = True
                        for output in modelCard["outputs"]:
                            sbom_document.addrow(["Output", output])
                    if title:
                        sbom_document.showtable(widths=[5, 9])

                    for dataset in modelCard["dataset"]:
                        sbom_document.heading(1, "Model Dataset")
                        sbom_document.createtable(["Parameter", "Value"], [20, 35])
                        sbom_document.addrow(["Type", dataset["dataset_type"]])
                        if dataset.get("Name") is not None:
                            sbom_document.addrow(["Name", dataset["name"]])
                        if dataset.get("Id") is not None:
                            sbom_document.addrow(["Id", dataset["id"]])
                        # Contents
                        if "content" in dataset:
                            sbom_document.addrow(["Contents", dataset["content"]])
                        if "url" in dataset:
                            sbom_document.addrow(["Contents URL", dataset["url"]])
                        if "property" in dataset:
                            sbom_document.addrow(["Properties"])
                            for property in dataset["property"]:
                                sbom_document.addrow([property[0], property[1]])
                        sbom_document.addrow(
                            ["Classification", dataset["classification"]]
                        )
                        if "sensitive_data" in dataset:
                            sbom_document.addrow(
                                ["Sensitive Data", dataset["sensitive_data"]]
                            )
                        if "description" in dataset:
                            sbom_document.addrow(
                                ["Description", dataset["description"]]
                            )
                        sbom_document.showtable(widths=[5, 9])
                        # Graphics
                        if "graphics" in dataset:
                            sbom_document.heading(
                                2, f"Graphics - {dataset['graphics']['description']}"
                            )
                            sbom_document.createtable(["Name", "Content"])
                            for image in dataset["graphics"]["collection"]:
                                sbom_document.addrow([image[0], image[1]])
                            sbom_document.showtable(widths=[5, 9])

                        # Governance
                        title = False
                        if "custodian" in dataset:
                            if not title:
                                sbom_document.heading(1, "Dataset Governance")
                                sbom_document.createtable(
                                    ["Category", "Organization", "Contact"],
                                    [10, 15, 30],
                                )
                                title = True
                            for custodian in dataset["custodian"]:
                                sbom_document.addrow(
                                    [
                                        "Custodian",
                                        custodian.get("organization"),
                                        custodian.get("contact"),
                                    ]
                                )
                        if "steward" in dataset:
                            if not title:
                                sbom_document.heading(1, "Dataset Governance")
                                sbom_document.createtable(
                                    ["Category", "Organization", "Contact"],
                                    [10, 15, 30],
                                )
                                title = True
                            for steward in dataset["steward"]:
                                sbom_document.addrow(
                                    [
                                        "Steward",
                                        steward.get("organization"),
                                        steward.get("contact"),
                                    ]
                                )
                        if "owner" in dataset:
                            if not title:
                                sbom_document.heading(1, "Dataset Governance")
                                sbom_document.createtable(
                                    ["Category", "Organization", "Contact"],
                                    [10, 15, 30],
                                )
                                title = True
                            for owner in dataset["owner"]:
                                sbom_document.addrow(
                                    [
                                        "Owner",
                                        owner.get("organization"),
                                        owner.get("contact"),
                                    ]
                                )
                        if title:
                            sbom_document.showtable(widths=[4, 5, 5])

                    # Quantitative Analysis
                    title = False
                    if "performance" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Quantitative Analysis")
                            title = True
                        sbom_document.heading(2, "Performance Metrics")
                        sbom_document.createtable(
                            ["Type", "Value", "Slice", "Lower Bound", "Upper Bound"],
                            [10, 10, 10, 15, 15],
                        )
                        for performance in modelCard["performance"]:
                            sbom_document.addrow(
                                [
                                    performance[0],
                                    performance[1],
                                    performance[2],
                                    performance[3],
                                    performance[4],
                                ]
                            )
                        sbom_document.showtable(widths=[3, 3, 2, 3, 3])
                    if "graphics" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Quantitative Analysis")
                            title = True
                        sbom_document.heading(
                            2, f"Graphics - {modelCard['graphics']['description']}"
                        )
                        sbom_document.createtable(["Name", "Content"])
                        for image in modelCard["graphics"]["collection"]:
                            sbom_document.addrow([image[0], image[1]])
                        sbom_document.showtable(widths=[5, 9])

                    # Considerations
                    title = False
                    if "user" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Considerations")
                            sbom_document.createtable(["Category", "Value"], [20, 35])
                            title = True
                        for user in modelCard["user"]:
                            sbom_document.addrow(["Users", user])
                    if "usecase" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Considerations")
                            sbom_document.createtable(["Category", "Value"], [20, 35])
                            title = True
                        for usecase in modelCard["usecase"]:
                            sbom_document.addrow(["Use Cases", usecase])
                    if "limitation" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Considerations")
                            sbom_document.createtable(["Category", "Value"], [20, 35])
                            title = True
                        for limitation in modelCard["limitation"]:
                            sbom_document.addrow(["Technical Limitations", limitation])
                    if "tradeoff" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Considerations")
                            sbom_document.createtable(["Category", "Value"], [20, 35])
                            title = True
                        for tradeoff in modelCard["tradeoff"]:
                            sbom_document.addrow(["Performance TradeOffs", tradeoff])
                    if "ethicalrisk" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Considerations")
                            sbom_document.createtable(["Category", "Value"], [20, 35])
                            title = True
                        for consideration in modelCard["ethicalrisk"]:
                            sbom_document.addrow(
                                ["Ethical Considerations", consideration[0]]
                            )
                            sbom_document.addrow(
                                [
                                    "Ethical Considerations - Mitigation Strategy",
                                    consideration[1],
                                ]
                            )
                    if "fairness" in modelCard:
                        if not title:
                            sbom_document.heading(1, "Considerations")
                            sbom_document.createtable(["Category", "Value"], [20, 35])
                            title = True
                        print("Fairness Assessment")
                        for assessment in modelCard["fairness"]:
                            sbom_document.addrow(
                                ["Fairness Assessment - Group at Risk", assessment[0]]
                            )
                            sbom_document.addrow(
                                ["Fairness Assessment - Benefits", assessment[1]]
                            )
                            sbom_document.addrow(
                                ["Fairness Assessment - Harms", assessment[2]]
                            )
                            sbom_document.addrow(
                                [
                                    "Fairness Assessment - Mitigation Strategy",
                                    assessment[3],
                                ]
                            )
                    if title:
                        sbom_document.showtable(widths=[5, 9])
                    if "property" in modelCard:
                        # Potentially multiple entries
                        sbom_document.heading(1, "Properties")
                        sbom_document.createtable(["Name", "Value"], [20, 35])
                        for property in modelCard["property"]:
                            sbom_document.addrow([property[0], property[1]])
                        sbom_document.showtable(widths=[5, 9])

    sbom_document.publish(outfile)
