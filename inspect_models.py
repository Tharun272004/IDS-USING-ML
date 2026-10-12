import joblib
import os

files = [
    "models/ids_model.pkl",
    "models/protocol_encoder.pkl",
    "models/live_ids_model.pkl",
    "models/experimental_live_ids_model.pkl",
    "models/experimental_protocol_encoder.pkl",
]

for file in files:
    print("\n" + "=" * 70)
    print(file)
    print("=" * 70)

    try:
        obj = joblib.load(file)

        print("Type:", type(obj))

        if hasattr(obj, "get_params"):
            print("\nModel parameters:")
            print(obj.get_params())

        if hasattr(obj, "classes_"):
            print("\nClasses:")
            print(obj.classes_)

        if hasattr(obj, "feature_names_in_"):
            print("\nFeatures:")
            print(obj.feature_names_in_)

        if hasattr(obj, "categories_"):
            print("\nEncoder categories:")
            print(obj.categories_)

        if hasattr(obj, "__dict__"):
            print("\nAttributes:")
            for key, value in obj.__dict__.items():
                if key not in ["estimators_", "tree_"]:
                    print(f"  {key}: {value}")

    except Exception as e:
        print("ERROR:", type(e).__name__, "-", e)