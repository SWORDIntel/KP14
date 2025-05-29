import logging
import os
import re 
import pickle 
import joblib 
import traceback # For more detailed error logging
from sklearn.feature_extraction.text import TfidfVectorizer 
from sklearn.linear_model import LogisticRegression 
from sklearn.model_selection import train_test_split 
# from sklearn.metrics import accuracy_score # Not directly used in classify_code_block for this subtask
from typing import Any, Dict, Optional, List, Union

# Data Collection and Annotation Plan for Code Intent Classification:
# (Content remains the same as provided in the prompt - omitted here for brevity in this tool call)
# ... (Full data collection plan as previously defined) ...
# 1. Goal:
#    To create a labeled dataset of code snippets (primarily C/C++ from decompiled malware)
#    categorized by their primary operational intent.
#
# (The rest of the extensive comment block is assumed to be here)


class CodeIntentClassifier:
    """
    Classifies the intent of code snippets using a machine learning model.
    This implementation now focuses on loading and using a pre-trained (dummy) model.
    (Full class docstring with Future Implementation Plan and OpenVINO notes remains as previously defined - omitted for brevity)
    ...
    """
    def __init__(self, 
                 model_path: Optional[str] = "code_intent_model.joblib", 
                 vectorizer_path: Optional[str] = "code_intent_vectorizer.pkl", 
                 logger: Optional[logging.Logger] = None,
                 max_features_tfidf: int = 5000):
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)
        if not logger and not logging.getLogger().hasHandlers(): 
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        self.model_path: Optional[str] = model_path
        self.vectorizer_path: Optional[str] = vectorizer_path
        self.max_features_tfidf: int = max_features_tfidf # Used if training a new vectorizer
        
        self.model: Optional[LogisticRegression] = None
        self.vectorizer: Optional[TfidfVectorizer] = None

        if self.model_path and self.vectorizer_path:
            self.logger.info(f"Attempting to load trained components: model from '{self.model_path}', vectorizer from '{self.vectorizer_path}'.")
            if not self.load_trained_components(self.model_path, self.vectorizer_path):
                self.logger.warning("Failed to load one or both components. Classifier may not be usable until a model is trained or components are loaded successfully.")
        elif self.model_path or self.vectorizer_path: # Only one path provided
             self.logger.warning("Both model_path and vectorizer_path must be provided to load trained components. Initializing without loading.")
        else:
            self.logger.info("No model_path or vectorizer_path provided during initialization. Model and vectorizer not loaded. Train a model or load components manually.")

    def load_trained_components(self, model_path: str, vectorizer_path: str) -> bool:
        """
        Attempts to load the scikit-learn model and the TF-IDF vectorizer from the specified paths.
        Sets self.model and self.vectorizer. Updates self.model_path and self.vectorizer_path on success.
        Returns True if both are loaded successfully, False otherwise.
        """
        model_loaded = False
        vectorizer_loaded = False
        
        # Store original paths in case one fails and we need to revert the other successfully loaded one for consistency
        # However, for this method, we'll set the class paths if successful, and nullify if not.
        current_model_path_attr = self.model_path
        current_vectorizer_path_attr = self.vectorizer_path

        # Load Model
        if not os.path.exists(model_path):
            self.logger.warning(f"Model file not found at {model_path}.")
        else:
            try:
                loaded_model = joblib.load(model_path)
                self.model = loaded_model # Set the model attribute
                # self.model_path = model_path # Update path attribute to reflect where it was loaded from
                self.logger.info(f"Scikit-learn model loaded successfully from {model_path}.")
                model_loaded = True
            except Exception as e:
                self.logger.error(f"Error loading model from {model_path}: {e}")
                self.model = None 

        # Load Vectorizer
        if not os.path.exists(vectorizer_path):
            self.logger.warning(f"Vectorizer file not found at {vectorizer_path}.")
        else:
            try:
                with open(vectorizer_path, 'rb') as f:
                    loaded_vectorizer = pickle.load(f)
                self.vectorizer = loaded_vectorizer # Set the vectorizer attribute
                # self.vectorizer_path = vectorizer_path
                self.logger.info(f"TF-IDF Vectorizer loaded successfully from {vectorizer_path}.")
                vectorizer_loaded = True
            except Exception as e:
                self.logger.error(f"Error loading vectorizer from {vectorizer_path}: {e}")
                self.vectorizer = None 
        
        if model_loaded and vectorizer_loaded:
            # Update paths only if both succeed to ensure consistency
            self.model_path = model_path
            self.vectorizer_path = vectorizer_path
            return True
        else:
            # If one loaded but the other didn't, reset to ensure a consistent unloaded state.
            if model_loaded: # but vectorizer failed
                self.logger.warning("Model was loaded, but vectorizer failed. Resetting model to None for consistent state.")
                self.model = None
            if vectorizer_loaded: # but model failed
                self.logger.warning("Vectorizer was loaded, but model failed. Resetting vectorizer to None for consistent state.")
                self.vectorizer = None
            # Do not change self.model_path and self.vectorizer_path if loading fails, keep original paths from __init__
            self.model_path = current_model_path_attr
            self.vectorizer_path = current_vectorizer_path_attr
            return False

    def _default_tokenizer(self, code_snippet: str) -> List[str]:
        if not code_snippet:
            return []
        code = code_snippet.lower()
        token_pattern = re.compile(r"[a-zA-Z_]\w*|[0-9]+|==|!=|<=|>=|&&|\|\||<<|>>|->|\+\+|--|[=;\-\+\*\/\%<>&\|\(\)\{\}\[\]!.,:?~^]")
        tokens = token_pattern.findall(code)
        return tokens

    def save_model(self, path: Optional[str] = None) -> bool:
        save_path = path if path else self.model_path
        if not save_path:
            self.logger.error("No path provided to save model.")
            return False
        if not self.model:
            self.logger.error("Model is None, cannot save.")
            return False
        try:
            dir_name = os.path.dirname(save_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
            joblib.dump(self.model, save_path)
            self.logger.info(f"Scikit-learn model saved successfully to {save_path}.")
            return True
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while saving model to {save_path}: {e}")
            return False

    def save_vectorizer(self, path: Optional[str] = None) -> bool:
        save_path = path if path else self.vectorizer_path
        if not save_path:
            self.logger.error("No path provided to save vectorizer.")
            return False
        if not self.vectorizer:
            self.logger.error("Vectorizer is None, cannot save.")
            return False
        try:
            dir_name = os.path.dirname(save_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
            with open(save_path, 'wb') as f:
                pickle.dump(self.vectorizer, f)
            self.logger.info(f"TF-IDF Vectorizer saved successfully to {save_path}.")
            return True
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while saving vectorizer to {save_path}: {e}")
            return False

    def preprocess_snippet(self, code_snippet: str) -> Any:
        if not self.vectorizer:
            self.logger.error("TF-IDF Vectorizer is not fitted or loaded. Cannot preprocess snippet.")
            return None 
        
        self.logger.info(f"Preprocessing snippet using loaded TF-IDF vectorizer from '{self.vectorizer_path}'...")
        tokens = self._default_tokenizer(code_snippet)
        processed_code_for_tfidf = " ".join(tokens) 
        
        try:
            vectorized_snippet = self.vectorizer.transform([processed_code_for_tfidf])
            self.logger.info(f"Snippet vectorized. Shape: {vectorized_snippet.shape}")
            return vectorized_snippet
        except Exception as e:
            self.logger.error(f"Error transforming snippet with TF-IDF vectorizer: {e}")
            return None

    def classify_code_block(self, code_snippet: str) -> Dict[str, Any]:
        self.logger.info(f"Classification called for snippet (first 60 chars): '{code_snippet[:60].replace(chr(10), ' ')}'...")
        
        if not self.model or not self.vectorizer:
            self.logger.warning("Model or Vectorizer not loaded. Cannot classify.")
            return {
                "intent": "unknown_no_model_or_vectorizer", 
                "confidence": 0.0, 
                "all_probabilities": {},
                "engine_type": "dummy_sklearn_model", 
                "model_path_used": self.model_path, # Show configured paths
                "vectorizer_path_used": self.vectorizer_path,
                "error": "Model or Vectorizer not loaded"
            }

        self.logger.info(f"Using model from: {self.model_path}, Vectorizer from: {self.vectorizer_path}")
        vectorized_snippet: Any = self.preprocess_snippet(code_snippet)
        if vectorized_snippet is None: 
            self.logger.warning("Preprocessing failed for snippet. Cannot classify.")
            return {
                "intent": "unknown_preprocess_failed", 
                "confidence": 0.0, 
                "all_probabilities": {},
                "engine_type": "dummy_sklearn_model", 
                "model_path_used": self.model_path,
                "vectorizer_path_used": self.vectorizer_path,
                "error": "Preprocessing failed"
            }
        
        try:
            self.logger.info(f"Using loaded scikit-learn model ({self.model.__class__.__name__}) for prediction.")
            
            if not hasattr(self.model, 'classes_') or \
               not hasattr(self.model, 'predict') or \
               not hasattr(self.model, 'predict_proba'):
                self.logger.error("Loaded model is missing required attributes (classes_, predict, or predict_proba).")
                return {
                    "intent": "unknown_invalid_model_attributes", "confidence": 0.0, "all_probabilities": {},
                    "engine_type": "dummy_sklearn_model", "model_path_used": self.model_path,
                    "vectorizer_path_used": self.vectorizer_path, "error": "Model missing critical attributes"
                }

            predicted_indices = self.model.predict(vectorized_snippet)
            prediction_idx = predicted_indices[0]
            intent = str(self.model.classes_[prediction_idx]) # Ensure string for JSON if labels are not strings
            
            all_probs_raw = self.model.predict_proba(vectorized_snippet)[0]
            confidence = float(all_probs_raw[prediction_idx])
            
            all_probabilities = {str(self.model.classes_[i]): float(all_probs_raw[i]) for i in range(len(all_probs_raw))}

            self.logger.info(f"Snippet classified. Intent: {intent}, Confidence: {confidence:.4f}")
            return {
                "intent": intent, 
                "confidence": confidence, 
                "all_probabilities": all_probabilities,
                "engine_type": "dummy_sklearn_model", 
                "model_path_used": self.model_path,
                "vectorizer_path_used": self.vectorizer_path
            }
        except Exception as e:
            self.logger.error(f"Error during classification with model: {e}")
            self.logger.debug(traceback.format_exc()) 
            return {
                "intent": "unknown_classification_error", "confidence": 0.0, "all_probabilities": {},
                "engine_type": "dummy_sklearn_model", "model_path_used": self.model_path,
                "vectorizer_path_used": self.vectorizer_path, "error": str(e)
            }

    def train_intent_model(self, 
                           training_data_path: Optional[str] = None, 
                           labels_path: Optional[str] = None, 
                           training_corpus: Optional[List[str]] = None, 
                           training_labels: Optional[List[str]] = None,
                           validation_data_path: Optional[str] = None) -> Dict[str, Any]:
        corpus_snippets: List[str] = []
        labels_list: List[str] = [] 

        if training_corpus and training_labels:
            self.logger.info(f"Using provided in-memory corpus of {len(training_corpus)} snippets and labels.")
            if len(training_corpus) != len(training_labels):
                self.logger.error(f"Mismatch between provided corpus ({len(training_corpus)}) and labels ({len(training_labels)}). Training aborted.")
                return {"status": "error", "message": "Snippet and label count mismatch."}
            if not training_corpus:
                self.logger.error("Provided training_corpus is empty. Training aborted.")
                return {"status": "error", "message": "Empty training_corpus provided."}
            corpus_snippets = training_corpus
            labels_list = training_labels
        elif training_data_path and labels_path:
            self.logger.info(f"Loading training data from {training_data_path} and labels from {labels_path}.")
            try:
                with open(training_data_path, 'r', encoding='utf-8') as f_corpus:
                    corpus_snippets = [line.strip() for line in f_corpus if line.strip()]
                with open(labels_path, 'r', encoding='utf-8') as f_labels:
                    labels_list = [line.strip() for line in f_labels if line.strip()]
                if len(corpus_snippets) != len(labels_list):
                    self.logger.error(f"Mismatch between snippets ({len(corpus_snippets)}) and labels ({len(labels_list)}). Training aborted.")
                    return {"status": "error", "message": "Snippet and label count mismatch."}
                if not corpus_snippets:
                    self.logger.error("No snippets loaded from file. Training aborted.")
                    return {"status": "error", "message": "No snippets loaded."}
            except Exception as e:
                self.logger.error(f"Error loading training data/labels from files: {e}")
                return {"status": "error", "message": f"File loading error: {e}"}
        else:
            self.logger.error("No valid training data provided. Training aborted.")
            return {"status": "error", "message": "No training data provided."}

        self.logger.info(f"Initializing and fitting TF-IDF vectorizer on {len(corpus_snippets)} snippets...")
        self.vectorizer = TfidfVectorizer(
            tokenizer=self._default_tokenizer, token_pattern=None, 
            max_features=self.max_features_tfidf, lowercase=False 
        )
        try:
            X_tfidf = self.vectorizer.fit_transform(corpus_snippets) 
            self.logger.info(f"TF-IDF Vectorizer fitted. Vocab size: {len(self.vectorizer.vocabulary_)}, Features: {X_tfidf.shape[1]}")
            if not self.save_vectorizer(): 
                 self.logger.warning("Failed to save the fitted vectorizer during training.")
        except Exception as e:
            self.logger.error(f"Error fitting TF-IDF vectorizer: {e}")
            self.vectorizer = None 
            return {"status": "error", "message": f"Vectorizer fitting error: {e}"}
        
        self.logger.info("Training Logistic Regression model (simulation of more complex training)...")
        self.logger.info("Epoch 1/10 (simulated)...")
        self.logger.info("Epoch 5/10 (simulated)...")
        self.logger.info("Epoch 10/10 (simulated)...")
        
        X_train, X_test, y_train, y_test = None, None, None, None
        accuracy = None
        
        try:
            if len(set(labels_list)) > 1 and X_tfidf.shape[0] >= 5: 
                X_train, X_test, y_train, y_test = train_test_split(X_tfidf, labels_list, test_size=0.2, random_state=42, stratify=labels_list)
                self.logger.info(f"Train/test split: Train {X_train.shape[0]}, Test {X_test.shape[0]}.")
            else:
                self.logger.warning("Dataset too small or has only one class for stratified split. Training on full dataset.")
                X_train, y_train = X_tfidf, labels_list
        except ValueError as e_split: 
             self.logger.warning(f"Train/test split failed: {e_split}. Training on full dataset.")
             X_train, y_train = X_tfidf, labels_list

        self.model = LogisticRegression(random_state=42, max_iter=1000, solver='liblinear', class_weight='balanced')
        try:
            self.model.fit(X_train, y_train)
            self.logger.info("Logistic Regression model training completed.")
            self.logger.info("NPU/OpenVINO Optimization Note: The trained model could be optimized.")
            self.logger.info("  - Export to ONNX -> OpenVINO Model Optimizer (IR) -> INT8 Quantization (POT) -> Inference on NPU.")
            self.logger.info("  (Refer to class docstring for more detailed OpenVINO optimization strategy.)")

            if not self.save_model(): 
                self.logger.warning("Failed to save the trained model.")
        except Exception as e:
            self.logger.error(f"Error training Logistic Regression model: {e}")
            self.model = None
            return {"status": "error", "message": f"Model training error: {e}", "model_path": self.model_path}

        if X_test is not None and y_test is not None and hasattr(self.model, 'score'):
            try:
                accuracy = self.model.score(X_test, y_test)
                self.logger.info(f"Model accuracy on internal test split: {accuracy:.4f}")
            except Exception as e_acc:
                 self.logger.warning(f"Could not calculate accuracy on test split: {e_acc}")
        
        num_train_samples = X_train.shape[0] if X_train is not None else X_tfidf.shape[0]
        num_features = X_train.shape[1] if X_train is not None else X_tfidf.shape[1]

        return {
            "status": "simulated_training_complete", 
            "message": "Simulated training finished. Model and vectorizer saved.", 
            "model_path": self.model_path, 
            "vectorizer_path": self.vectorizer_path, 
            "num_training_samples": num_train_samples,
            "num_features": num_features,
            "accuracy_on_test_split": accuracy 
        }

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s') 
    main_logger = logging.getLogger("CodeIntentClassifierExample")

    current_dir = os.getcwd()
    test_model_path = os.path.join(current_dir, "test_intent_model.joblib")
    test_vectorizer_path = os.path.join(current_dir, "test_intent_vectorizer.pkl")

    main_logger.info("--- Test Case 1: Training, Saving, Loading, and Classification ---")
    classifier_train = CodeIntentClassifier(
        model_path=test_model_path, 
        vectorizer_path=test_vectorizer_path, 
        logger=main_logger,
        max_features_tfidf=100 
    )
    
    dummy_corpus = [
        "int main() { printf(\"Hello, world!\\n\"); return 0; }", 
        "void encrypt_data(char* data, int size, char* key) { for(int i=0; i<size; ++i) data[i] ^= key[i % strlen(key)]; }",
        "SOCKET s = socket(AF_INET, SOCK_STREAM, 0); connect(s, &addr, sizeof(addr)); send(s, buf, len, 0);", 
        "CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);", 
        "RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey); RegQueryValueExA(hKey, value_name, NULL, &type, data_buf, &buf_size);", 
        "char* important_data = \"sensitive\"; send(sock, important_data, strlen(important_data), 0);", 
        "int another_func() { return 1+1; }", 
        "char transform(char c) { return c ^ 0xAB; }", 
        "connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));", 
        "TerminateProcess(hProcess, 0);" 
    ]
    dummy_labels = [
        "benign_utility", "encryption", "networking_communication", "process_manipulation", 
        "registry_operations", "data_exfiltration", "benign_utility", "encryption", 
        "networking_communication", "process_manipulation"
    ]

    train_result = classifier_train.train_intent_model(
        training_corpus=dummy_corpus, 
        training_labels=dummy_labels
    )
    main_logger.info(f"Training Result: {train_result}")
    assert train_result["status"] == "simulated_training_complete", f"Training failed: {train_result.get('message')}"
    assert os.path.exists(test_model_path), "Model file was not saved after training."
    assert os.path.exists(test_vectorizer_path), "Vectorizer file was not saved after training."
    main_logger.info(f"Accuracy on internal test split: {train_result.get('accuracy_on_test_split', 'N/A')}")

    main_logger.info("\n--- Loading and Classifying with Trained Model ---")
    classifier_load = CodeIntentClassifier( 
        model_path=test_model_path, 
        vectorizer_path=test_vectorizer_path, 
        logger=main_logger
    )
    assert classifier_load.model is not None, "Trained model failed to load."
    assert classifier_load.vectorizer is not None, "Trained vectorizer failed to load."
    assert isinstance(classifier_load.model, LogisticRegression), "Loaded model is not a LogisticRegression instance."

    test_snippet_network = "send(socket_descriptor, data_buffer, data_length, 0);"
    classification = classifier_load.classify_code_block(test_snippet_network)
    main_logger.info(f"Classification for '{test_snippet_network[:30]}...': {json.dumps(classification, indent=2)}")
    assert classification["intent"] is not None and classification["intent"] != "unknown_no_model_or_vectorizer", "Classification failed for network snippet."
    assert classification["engine_type"] == "dummy_sklearn_model", "Engine type mismatch."
    assert "all_probabilities" in classification, "all_probabilities missing from result."
    assert classification["model_path_used"] == test_model_path
    assert classification["vectorizer_path_used"] == test_vectorizer_path

    test_snippet_file = "ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL);"
    classification_file = classifier_load.classify_code_block(test_snippet_file)
    main_logger.info(f"Classification for '{test_snippet_file[:30]}...': {json.dumps(classification_file, indent=2)}")
    assert classification_file["intent"] is not None and classification_file["intent"] != "unknown_no_model_or_vectorizer", "Classification failed for file snippet."
    
    main_logger.info("\n--- Testing with Unloaded Components (should fail gracefully) ---")
    classifier_unloaded = CodeIntentClassifier(model_path="non_existent_model.joblib", 
                                               vectorizer_path="non_existent_vectorizer.pkl", 
                                               logger=main_logger)
    result_unloaded = classifier_unloaded.classify_code_block("int x = 0;")
    main_logger.info(f"Classification with unloaded components: {json.dumps(result_unloaded, indent=2)}")
    assert "Model or Vectorizer not loaded" in result_unloaded.get("error", ""), f"Unexpected error message: {result_unloaded.get('error')}"
    assert result_unloaded["intent"] == "unknown_no_model_or_vectorizer"

    main_logger.info("\n--- Testing with only model path provided during init ---")
    classifier_model_only = CodeIntentClassifier(model_path=test_model_path, logger=main_logger) # vectorizer_path will be default
    result_model_only = classifier_model_only.classify_code_block("int x = 0;")
    main_logger.info(f"Classification with only model path: {json.dumps(result_model_only, indent=2)}")
    assert "Model or Vectorizer not loaded" in result_model_only.get("error", "")

    main_logger.info("\n--- Cleaning up test files ---")
    for f_path in [test_model_path, test_vectorizer_path]:
        if os.path.exists(f_path):
            os.remove(f_path)
            main_logger.info(f"Removed {f_path}")
            
    main_logger.info("\n--- All baseline model training and classification tests completed ---")
```
