# SDN DDoS Detection using Adaptive Random Forest

This project investigates the use of an Adaptive Random Forest (ARF) for online DDoS detection and attack classification in Software-Defined Networks (SDN).

## Project Objective

The main objective is to develop an online machine learning based DDoS detection system that can adapt to changing network traffic patterns without requiring conventional periodic model retraining.

The project uses the CICDDoS2019 dataset and explores:

- Multiclass DDoS attack classification
- Adaptive Random Forest
- Online/streaming machine learning
- Concept drift adaptation
- Dynamic feature selection
- SDN controller integration

## Dataset

The CICDDoS2019 dataset is not included in this repository because of its large size.

Each developer should obtain the dataset separately and place it in the local `datasets/` directory.

## Project Structure

```text
src/          Python source code
notebooks/    Jupyter notebooks
notes/        Project notes and documentation
results/      Experimental results
datasets/     Local dataset files (not tracked)
processed/    Local processed datasets (not tracked)
train_data/   Local training data (not tracked)
test_data/    Local testing data (not tracked)