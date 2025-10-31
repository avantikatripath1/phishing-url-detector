from sklearn.base import BaseEstimator, TransformerMixin
from scipy.sparse import csr_matrix

class FeatureUnionTransformer(BaseEstimator, TransformerMixin):
    def __init__(self, tfidf_vectorizer=None):
        self.tfidf = tfidf_vectorizer

    def fit(self, X, y=None):
        texts = X.ravel()
        if self.tfidf:
            self.tfidf.fit(texts)
        return self

    def transform(self, X):
        texts = X.ravel()
        if not self.tfidf:
            return csr_matrix((len(texts), 0))  # return empty sparse safely
        return self.tfidf.transform(texts)
