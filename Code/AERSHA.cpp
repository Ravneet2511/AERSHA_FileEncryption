#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <utility> // for pair

using namespace std;

class HybridEnc {
public:
    HybridEnc() { OpenSSL_add_all_algorithms(); ERR_load_crypto_strings(); }
    ~HybridEnc() { EVP_cleanup(); ERR_free_strings(); }

    bool genRSA(const string &privFile, const string &pubFile) {
        RSA *rsa = RSA_new();
        BIGNUM *bn = BN_new();
        BN_set_word(bn, RSA_F4);
        if (RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
            RSA_free(rsa);
            BN_free(bn);
            return false;
        }
        FILE *fp = fopen(privFile.c_str(), "wb");
        if (!fp) { RSA_free(rsa); BN_free(bn); return false; }
        PEM_write_RSAPrivateKey(fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(fp);

        fp = fopen(pubFile.c_str(), "wb");
        if (!fp) { RSA_free(rsa); BN_free(bn); return false; }
        PEM_write_RSA_PUBKEY(fp, rsa);
        fclose(fp);

        RSA_free(rsa);
        BN_free(bn);
        return true;
    }

    vector<unsigned char> genAESKey() {
        vector<unsigned char> key(32);
        if (RAND_bytes(key.data(), 32) != 1) {
            cerr << "Error generating AES key." << endl;
            key.clear();
        }
        return key;
    }

    vector<unsigned char> genIV() {
        vector<unsigned char> iv(16);
        if (RAND_bytes(iv.data(), 16) != 1) {
            cerr << "Error generating IV." << endl;
            iv.clear();
        }
        return iv;
    }

    vector<unsigned char> encAESKey(const vector<unsigned char>& key, const string &pubFile) {
        vector<unsigned char> enc;
        FILE *fp = fopen(pubFile.c_str(), "rb");
        if (!fp) return enc;
        RSA *rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (!rsa) return enc;
        int size = RSA_size(rsa);
        enc.resize(size);
        int res = RSA_public_encrypt(key.size(), key.data(), enc.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        RSA_free(rsa);
        if (res == -1) { enc.clear(); return enc; }
        enc.resize(res);
        return enc;
    }

    vector<unsigned char> decAESKey(const vector<unsigned char>& enc, const string &privFile) {
        vector<unsigned char> dec;
        FILE *fp = fopen(privFile.c_str(), "rb");
        if (!fp) return dec;
        RSA *rsa = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (!rsa) return dec;
        int size = RSA_size(rsa);
        dec.resize(size);
        int res = RSA_private_decrypt(enc.size(), enc.data(), dec.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        RSA_free(rsa);
        if (res == -1) { dec.clear(); return dec; }
        dec.resize(res);
        return dec;
    }

    bool aesEncFile(const string &inF, const string &outF, 
                    const vector<unsigned char>& key, const vector<unsigned char>& iv) {
        ifstream ifs(inF, ios::binary);
        ofstream ofs(outF, ios::binary);
        if (!ifs) { cerr << "Cannot open input file: " << inF << endl; return false; }
        if (!ofs) { cerr << "Cannot open output file: " << outF << endl; return false; }
        ofs.write(reinterpret_cast<const char*>(iv.data()), iv.size());

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { cerr << "Error creating encryption context." << endl; return false; }
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            cerr << "Error initializing encryption." << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        const int bufSize = 4096;
        vector<unsigned char> inbuf(bufSize), outbuf(bufSize + AES_BLOCK_SIZE);
        int outLen = 0;
        while (ifs) {
            ifs.read(reinterpret_cast<char*>(inbuf.data()), bufSize);
            int r = ifs.gcount();
            if (r > 0) {
                if (EVP_EncryptUpdate(ctx, outbuf.data(), &outLen, inbuf.data(), r) != 1) {
                    cerr << "Encryption update error." << endl;
                    EVP_CIPHER_CTX_free(ctx);
                    return false;
                }
                ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
            }
        }
        if (EVP_EncryptFinal_ex(ctx, outbuf.data(), &outLen) != 1) {
            cerr << "Encryption finalization error." << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    bool aesDecFile(const string &inF, const string &outF, const vector<unsigned char>& key) {
        ifstream ifs(inF, ios::binary);
        ofstream ofs(outF, ios::binary);
        if (!ifs) { cerr << "Cannot open input file: " << inF << endl; return false; }
        if (!ofs) { cerr << "Cannot open output file: " << outF << endl; return false; }

        vector<unsigned char> iv(16);
        ifs.read(reinterpret_cast<char*>(iv.data()), iv.size());
        if (ifs.gcount() != static_cast<streamsize>(iv.size())) {
            cerr << "Error reading IV from file." << endl;
            return false;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { cerr << "Error creating decryption context." << endl; return false; }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            cerr << "Error initializing decryption." << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        const int bufSize = 4096;
        vector<unsigned char> inbuf(bufSize), outbuf(bufSize + AES_BLOCK_SIZE);
        int outLen = 0;
        while (ifs) {
            ifs.read(reinterpret_cast<char*>(inbuf.data()), bufSize);
            int r = ifs.gcount();
            if (r > 0) {
                if (EVP_DecryptUpdate(ctx, outbuf.data(), &outLen, inbuf.data(), r) != 1) {
                    cerr << "Decryption update error." << endl;
                    EVP_CIPHER_CTX_free(ctx);
                    return false;
                }
                ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
            }
        }
        if (EVP_DecryptFinal_ex(ctx, outbuf.data(), &outLen) != 1) {
            cerr << "Decryption finalization error." << endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    bool signFile(const string &inF, const string &sigFile, const string &privKeyFile) {
        ifstream ifs(inF, ios::binary);
        if (!ifs) {
            cerr << "Cannot open input file for signing: " << inF << endl;
            return false;
        }
        vector<unsigned char> data((istreambuf_iterator<char>(ifs)), {});
        ifs.close();

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), hash);

        FILE *fp = fopen(privKeyFile.c_str(), "rb");
        if (!fp) { cerr << "Cannot open private key file: " << privKeyFile << endl; return false; }
        RSA *rsa = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (!rsa) { cerr << "Invalid private key." << endl; return false; }

        unsigned int sigLen = RSA_size(rsa);
        vector<unsigned char> signature(sigLen);
        if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &sigLen, rsa) != 1) {
            cerr << "RSA_sign failed." << endl;
            RSA_free(rsa);
            return false;
        }
        RSA_free(rsa);
        signature.resize(sigLen);

        ofstream ofs(sigFile, ios::binary);
        if (!ofs) { cerr << "Cannot open signature file: " << sigFile << endl; return false; }
        ofs.write(reinterpret_cast<const char*>(signature.data()), signature.size());
        ofs.close();

        cout << "Signature created successfully and saved to " << sigFile << endl;
        return true;
    }

    bool verifySignature(const string &inF, const string &sigFile, const string &pubKeyFile) {
        ifstream ifs(inF, ios::binary);
        if (!ifs) {
            cerr << "Cannot open input file for verification: " << inF << endl;
            return false;
        }
        vector<unsigned char> data((istreambuf_iterator<char>(ifs)), {});
        ifs.close();

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), hash);

        ifstream sigifs(sigFile, ios::binary);
        if (!sigifs) { cerr << "Cannot open signature file: " << sigFile << endl; return false; }
        vector<unsigned char> signature((istreambuf_iterator<char>(sigifs)), {});
        sigifs.close();

        FILE *fp = fopen(pubKeyFile.c_str(), "rb");
        if (!fp) { cerr << "Cannot open public key file: " << pubKeyFile << endl; return false; }
        RSA *rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (!rsa) { cerr << "Invalid public key." << endl; return false; }

        bool result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                                 signature.data(), signature.size(), rsa) == 1;
        RSA_free(rsa);

        if (result) {
            cout << "Signature verified successfully." << endl;
        } else {
            cout << "Signature verification failed." << endl;
        }
        return result;
    }

    pair<string, string> splitFilename(const string &filename) {
        size_t lastDot = filename.find_last_of('.');
        if (lastDot == string::npos) {
            return make_pair(filename, "");
        } else {
            return make_pair(filename.substr(0, lastDot), filename.substr(lastDot));
        }
    }

    void displayMenu() {
        cout << "\n--- Hybrid Encryption/Decryption System ---" << endl;
        cout << "1. Generate RSA Key Pair" << endl;
        cout << "2. Encrypt and Sign File" << endl;
        cout << "3. Decrypt and Verify File" << endl;
        cout << "4. Exit" << endl;
        cout << "Enter your choice: ";
    }

    void generateKeys() {
        string sender_priv = "sender_priv.pem";
        string sender_pub = "sender_pub.pem";
        string recipient_priv = "recipient_priv.pem";
        string recipient_pub = "recipient_pub.pem";

        cout << "\nGenerating RSA key pairs..." << endl;
        if (!genRSA(sender_priv, sender_pub)) {
            cerr << "Failed to generate sender keys." << endl;
            return;
        }
        if (!genRSA(recipient_priv, recipient_pub)) {
            cerr << "Failed to generate recipient keys." << endl;
            return;
        }
        cout << "RSA key pairs generated successfully!" << endl;
        cout << "Files created:" << endl;
        cout << "- Sender: " << sender_priv << " (private), " << sender_pub << " (public)" << endl;
        cout << "- Recipient: " << recipient_priv << " (private), " << recipient_pub << " (public)" << endl;
    }

    void encryptAndSign() {
        string input_file;
        cout << "\nEnter the name of the file to encrypt and sign: ";
        cin >> input_file;

        pair<string, string> split = splitFilename(input_file);
        string base = split.first;
        string extension = split.second;

        string encrypted_file = base + "_encrypted" + extension;
        string encrypted_key_file = "encrypted_key.enc";
        string signature_file = encrypted_file + "_signature.sig";

        string recipient_pub = "recipient_pub.pem";
        string sender_priv = "sender_priv.pem";
    

        // Check if required files exist
        ifstream pubKey(recipient_pub);
        if (!pubKey) {
            cerr << "Recipient public key not found!" << endl;
            return;
        }
        pubKey.close();

        ifstream privKey(sender_priv);
        if (!privKey) {
            cerr << "Sender private key not found!" << endl;
            return;
        }
        privKey.close();

        vector<unsigned char> aesKey = genAESKey();
        if (aesKey.empty()) {
            cerr << "Failed to generate AES key" << endl;
            return;
        }

        vector<unsigned char> iv = genIV();
        if (iv.empty()) {
            cerr << "Failed to generate IV" << endl;
            return;
        }

        if (!aesEncFile(input_file, encrypted_file, aesKey, iv)) {
            cerr << "File encryption failed" << endl;
            return;
        }

        vector<unsigned char> encKey = encAESKey(aesKey, recipient_pub);
        if (encKey.empty()) {
            cerr << "Failed to encrypt AES key" << endl;
            return;
        }

        ofstream keyOut(encrypted_key_file, ios::binary);
        if (!keyOut) {
            cerr << "Failed to save encrypted key" << endl;
            return;
        }
        keyOut.write(reinterpret_cast<const char*>(encKey.data()), encKey.size());
        keyOut.close();

        if (!signFile(encrypted_file, signature_file, sender_priv)) {
            cerr << "Failed to sign file" << endl;
            return;
        }

        cout << "\nFile encrypted and signed successfully!" << endl;
        cout << "Output files:" << endl;
        cout << "- Encrypted file: " << encrypted_file << endl;
        cout << "- Encrypted key: " << encrypted_key_file << endl;
        cout << "- Signature: " << signature_file << endl;
    }

    void decryptAndVerify() {
        string encrypted_file;
        cout << "\nEnter the name of the encrypted file to decrypt and verify: ";
        cin >> encrypted_file;

        pair<string, string> split = splitFilename(encrypted_file);
        string base = split.first;
        string extension = split.second;

        string decrypted_file = base + "_decrypted" + extension;
        string encrypted_key_file = "encrypted_key.enc";
        string signature_file = encrypted_file + "_signature.sig";

        string recipient_priv = "recipient_priv.pem";
        string sender_pub = "sender_pub.pem";

        // Check if required files exist
        ifstream encFile(encrypted_file);
        if (!encFile) {
            cerr << "Encrypted file not found!" << endl;
            return;
        }
        encFile.close();

        ifstream keyFile(encrypted_key_file);
        if (!keyFile) {
            cerr << "Encrypted key file not found!" << endl;
            return;
        }
        keyFile.close();

        ifstream sigFile(signature_file);
        if (!sigFile) {
            cerr << "Signature file not found!" << endl;
            return;
        }
        sigFile.close();

        ifstream privKey(recipient_priv);
        if (!privKey) {
            cerr << "Recipient private key not found!" << endl;
            return;
        }
        privKey.close();

        ifstream pubKey(sender_pub);
        if (!pubKey) {
            cerr << "Sender public key not found !" << endl;
            return;
        }
        pubKey.close();

        // Read encrypted key
        ifstream keyStream(encrypted_key_file, ios::binary);
        vector<unsigned char> encKey((istreambuf_iterator<char>(keyStream)), {});
        keyStream.close();

        vector<unsigned char> aesKey = decAESKey(encKey, recipient_priv);
        if (aesKey.empty()) {
            cerr << "Failed to decrypt AES key" << endl;
            return;
        }

        if (!aesDecFile(encrypted_file, decrypted_file, aesKey)) {
            cerr << "File decryption failed" << endl;
            return;
        }

        if (!verifySignature(encrypted_file, signature_file, sender_pub)) {
            cerr << "Signature verification failed." << endl;
            return;
        }

        cout << "\nFile decrypted and verified successfully!" << endl;
        cout << "Decrypted file: " << decrypted_file << endl;
    }

    void run() {
        int choice;
        while (true) {
            displayMenu();
            cin >> choice;
            switch (choice) {
                case 1:
                    generateKeys();
                    break;
                case 2:
                    encryptAndSign();
                    break;
                case 3:
                    decryptAndVerify();
                    break;
                case 4:
                    cout << "Exiting program." << endl;
                    return;
                default:
                    cout << "Invalid choice. Please try again." << endl;
            }
        }
    }
};

int main() {
    HybridEnc hybridEnc;
    hybridEnc.run();
    return 0;
}