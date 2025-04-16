# Phishing URL Detection: Random Forest Classification

## Description

The purpose of this model is to classify wether or not a URL is legitimate, or a phishing attempt. Phishing is a type of social engineering attack often used to steal user data, including login credentials and credit card numbers. In this case, phishing is determined from the URL - including special characters, redirects, ssl, and domain information.

The model employs RandomForest Classification to make these predictions. Random Forest Classification is a machine learning algorithm that uses an ensemble of decision trees to make predictions, particularly for classification tasks. It combines the predictions of multiple, uncorrelated decision trees to improve accuracy and robustness. 

To test the final model, execute `streamlit run app.py`. You can also run it via the deployed model [here]().

## Data Acquisition

The original data aqcuired from Kaggle can be accessed through the link provided below:
- [Download Data](https://www.kaggle.com/datasets/danielfernandon/web-page-phishing-dataset)

### Key Features of the Dataset

- **url_length**:  The length of the URL.

- **n_slash**: The count of ‘/’ characters in the URL.

- **n_questionmark**: The count of ‘?’ characters in the URL.

- **n_equal**: The count of ‘=’ characters in the URL.

- **n_at**: The count of ‘@’ characters in the URL.

- **n_and**:  The count of ‘&’ characters in the URL.

- **n_exclamation**: The count of ‘!’ characters in the URL.

- **n_asterisk**: The count of ‘*’ characters in the URL.

- **n_hastag**: The count of ‘#’ characters in the URL.

- **n_percent**: The count of ‘%’ characters in the URL.

- **dots_per_length**: The amount of '.' per URL query.

- **hyphens_per_length**: The amount of '-' per URL query.

- **is_long_url**: Is the URL query an abnormally long string.

- **has_many_dots**: Does it have abnomormal amounts of '.'

- **has_ssl**: Does it have an SSL certificate.

- **is_cloudflare_protected**: Is the URL Cloudflare protected.

- **digit_count**: How many numbers are within the URL.

- **special_char_density**: Ratio of special characters (*&@#) within URL.

- **suspicious_tld_risk**: Risk of URL containing suspicious extensions, domains, and patterns.

- **has_redirects**: Does URL have redirects.

- **risk_score**: Ultimate risk score of URL based on characteristics.

- **url_complexity**: Ultimate URL complexity based on characteristics.

- **phishing**: The Labels of the URL. 1 is phishing and 0 is legitimate.

## Features
- Data cleaning and preprocessing
- Statistical, univariate, and bivariate analysis.
- Visualization of data distributions and relationships.
- Training, evaluation, and deployment of Random Forest model.

## Project Structure
- **data/:** Contains the dataset used for modelling.
- **model/:**
    - `notebook.ipynb`: Jupyter notebook detailing the training process.
    - `requirements.txt`: Requirements for jupyter notebook.
- **app.py**: Streamlit application code for deployment.
- **requirements.txt**: Requirements for streamlit app.
- **README.md:** Project documentation.

## Installation
### Prerequisites
- `Python` Version: 3.13.2 | packaged by Anaconda
- `jupyter` notebook version 7.3.3
- Install the required libraries using: `pip install -r requirements.txt`.

### Running the Notebook

1. Open the `.ipynb` file in Jupyter by running: `jupyter notebook`.
2. Run all cells in the notebook.

## Sample Visualization

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contact
For questions or suggestions, please contact me via the email on my profile or [LinkedIn](https://www.linkedin.com/in/christine-coomans/).