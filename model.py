import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from sklearn.pipeline import Pipeline

train = pd.read_csv('data/dataset_malwares.csv')
test = pd.read_csv('data/dataset_test.csv', sep=',')

list_drop_train = ['Name', 'Malware', 'SuspiciousNameSection', 'SuspiciousImportFunctions',
                   'SectionsLength', 'SectionMaxPhysical', 'SectionMinPhysical', 'SectionMaxVirtual',
                   'SectionMinVirtual', 'SectionMaxPointerData', 'SectionMinPointerData', 'SectionMaxChar',
                   'SectionMainChar', 'DirectoryEntryImport', 'DirectoryEntryImportSize',
                   'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport',
                   'ImageDirectoryEntryResource', 'ImageDirectoryEntryException', 'ImageDirectoryEntrySecurity']

list_drop_test = ['Name', 'SuspiciousNameSection', 'SuspiciousImportFunctions',
                  'SectionsLength', 'SectionMaxPhysical', 'SectionMinPhysical', 'SectionMaxVirtual',
                  'SectionMinVirtual', 'SectionMaxPointerData', 'SectionMinPointerData', 'SectionMaxChar',
                  'SectionMainChar', 'DirectoryEntryImport', 'DirectoryEntryImportSize',
                  'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport',
                  'ImageDirectoryEntryResource', 'ImageDirectoryEntryException', 'ImageDirectoryEntrySecurity']

# The target is Malware Column {0=Benign, 1=Malware}
X = train.drop(list_drop_train, axis=1)
y = train['Malware']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=101)

# Feature Scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)

X_new = pd.DataFrame(X_scaled, columns=X.columns)

# Principal Component Analysis
skpca = PCA(n_components=55)
X_pca = skpca.fit_transform(X_new)
print('Variance sum : ', skpca.explained_variance_ratio_.cumsum()[-1])

# Build The Model
model = RandomForestClassifier(n_estimators=100, random_state=0, oob_score=True, max_depth=16, max_features='sqrt')
model.fit(X_pca, y_train)

X_test_scaled = scaler.transform(X_test)
X_new_test = pd.DataFrame(X_test_scaled, columns=X.columns)
X_test_pca = skpca.transform(X_new_test)

# Predict
y_pred = model.predict(X_test_pca)

# Check test set
print(classification_report(y_pred, y_test))

# Construct pipeline
pipe = Pipeline([('scale', scaler), ('pca', skpca), ('clf', model)])

X_testing = test.drop(list_drop_test, axis=1)

X_testing_scaled = pipe.named_steps['scale'].transform(X_testing)
X_testing_pca = pipe.named_steps['pca'].transform(X_testing_scaled)
y_testing_pred = pipe.named_steps['clf'].predict_proba(X_testing_pca)

# Print result
print(pd.concat([test['Name'], pd.DataFrame(y_testing_pred)], axis=1))

# Get model in pickle format
with open('./model.pkl', 'wb') as model_pkl:
    pickle.dump(pipe, model_pkl)
