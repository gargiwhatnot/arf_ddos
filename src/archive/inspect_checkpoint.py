import os
import pickle

# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "../results/arf_checkpoint.pkl"


# ============================================================
# LOAD CHECKPOINT
# ============================================================

print("=" * 70)
print("ARF CHECKPOINT INSPECTION")
print("=" * 70)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Checkpoint not found:\n{MODEL_PATH}"
    )

print(f"\nLoading:\n{MODEL_PATH}")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("\nCheckpoint loaded successfully.")

print("\nModel type:")
print(type(model))


# ============================================================
# BASIC MODEL INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("MODEL INFORMATION")
print("=" * 70)

print("\nNumber of trees:")

try:
    print(len(model.models))
except Exception as e:
    print("Could not determine number of trees.")
    print("Error:", e)


# ============================================================
# INSPECT EACH TREE
# ============================================================

print("\n" + "=" * 70)
print("TREE-BY-TREE INSPECTION")
print("=" * 70)

for tree_number, tree in enumerate(model.models, start=1):

    print(f"\n--- TREE {tree_number} ---")

    print("Tree type:")
    print(type(tree))

    # --------------------------------------------------------
    # Try to inspect the underlying model
    # --------------------------------------------------------

    if hasattr(tree, "model"):

        print("\nUnderlying tree model:")
        print(type(tree.model))

        print("\nUnderlying model:")
        print(tree.model)

    else:
        print("\nNo direct 'model' attribute found.")

    # --------------------------------------------------------
    # Warning / drift information
    # --------------------------------------------------------

    print("\nWarning detector:")
    try:
        print(tree.warning_detection)
    except Exception:
        print("Not directly accessible.")

    print("\nDrift detector:")
    try:
        print(tree.drift_detection)
    except Exception:
        print("Not directly accessible.")


# ============================================================
# DRIFT INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("ARF DRIFT INFORMATION")
print("=" * 70)

try:
    print(
        "\nTotal warnings detected:",
        model.n_warnings_detected()
    )
except Exception as e:
    print(
        "\nCould not read total warnings."
    )
    print("Error:", e)

try:
    print(
        "Total drifts detected:",
        model.n_drifts_detected()
    )
except Exception as e:
    print(
        "Could not read total drifts."
    )
    print("Error:", e)


# ============================================================
# DRIFT INFORMATION PER TREE
# ============================================================

print("\nPer-tree drift information:")

for tree_number in range(len(model.models)):

    tree_id = tree_number

    try:
        warnings = model.n_warnings_detected(tree_id)
    except Exception:
        warnings = "N/A"

    try:
        drifts = model.n_drifts_detected(tree_id)
    except Exception:
        drifts = "N/A"

    print(
        f"Tree {tree_number + 1}: "
        f"warnings={warnings}, "
        f"drifts={drifts}"
    )


# ============================================================
# CHECK MODEL OBJECT ATTRIBUTES
# ============================================================

print("\n" + "=" * 70)
print("MODEL ATTRIBUTES")
print("=" * 70)

attributes = [
    "models",
    "n_models",
    "max_features",
    "seed",
    "classes",
    "classes_seen",
    "class_counts"
]

for attribute in attributes:

    if hasattr(model, attribute):

        try:
            value = getattr(model, attribute)

            print(
                f"\n{attribute}:"
            )
            print(value)

        except Exception as e:

            print(
                f"\n{attribute}: "
                f"<could not read: {e}>"
            )

    else:

        print(
            f"\n{attribute}: "
            f"NOT AVAILABLE"
        )


# ============================================================
# DONE
# ============================================================

print("\n" + "=" * 70)
print("INSPECTION COMPLETE")
print("=" * 70)

print(
    "\nIMPORTANT:"
    "\nThis script only inspected the checkpoint."
    "\nIt did NOT train the ARF."
    "\nIt did NOT call learn_one()."
    "\nIt did NOT modify the checkpoint."
)