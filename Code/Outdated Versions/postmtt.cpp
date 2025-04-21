#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>


class HybridEnc {
public:
    HybridEnc() { OpenSSL_add_all_algorithms(); ERR_load_crypto_strings(); }
    ~HybridEnc() { EVP_cleanup(); ERR_free_strings(); }

    // Generate an RSA key pair and save to files
    bool genRSA(const std::string &privFile, const std::string &pubFile) {
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

    // Generate random AES key (32 bytes) and IV (16 bytes)
    std::vector<unsigned char> genAESKey() {
        std::vector<unsigned char> key(32);
        if (RAND_bytes(key.data(), 32) != 1) {
            std::cerr << "Error generating AES key." << std::endl;
            key.clear();
        }
        return key;
    }
    
    std::vector<unsigned char> genIV() {
        std::vector<unsigned char> iv(16);
        if (RAND_bytes(iv.data(), 16) != 1) {
            std::cerr << "Error generating IV." << std::endl;
            iv.clear();
        }
        return iv;
    }
    
    // Encrypt the AES key using RSA public key
    std::vector<unsigned char> encAESKey(const std::vector<unsigned char>& key, const std::string &pubFile) {
        std::vector<unsigned char> enc;
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
    
    // Decrypt the AES key using RSA private key
    std::vector<unsigned char> decAESKey(const std::vector<unsigned char>& enc, const std::string &privFile) {
        std::vector<unsigned char> dec;
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
    
    // Encrypt file using AES-256-CBC (IV written at file start)
    bool aesEncFile(const std::string &inF, const std::string &outF, 
                    const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
        std::ifstream ifs(inF, std::ios::binary);
        std::ofstream ofs(outF, std::ios::binary);
        if (!ifs) { std::cerr << "Cannot open input file: " << inF << std::endl; return false; }
        if (!ofs) { std::cerr << "Cannot open output file: " << outF << std::endl; return false; }
        // Write IV at beginning of output file
        ofs.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { std::cerr << "Error creating encryption context." << std::endl; return false; }
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            std::cerr << "Error initializing encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        const int bufSize = 4096;
        std::vector<unsigned char> inbuf(bufSize), outbuf(bufSize + AES_BLOCK_SIZE);
        int outLen = 0;
        while (ifs) {
            ifs.read(reinterpret_cast<char*>(inbuf.data()), bufSize);
            int r = ifs.gcount();
            if (r > 0) {
                if (EVP_EncryptUpdate(ctx, outbuf.data(), &outLen, inbuf.data(), r) != 1) {
                    std::cerr << "Encryption update error." << std::endl;
                    EVP_CIPHER_CTX_free(ctx);
                    return false;
                }
                ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
            }
        }
        if (EVP_EncryptFinal_ex(ctx, outbuf.data(), &outLen) != 1) {
            std::cerr << "Encryption finalization error." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    // Decrypt file using AES-256-CBC (reads IV from file start)
    bool aesDecFile(const std::string &inF, const std::string &outF, const std::vector<unsigned char>& key) {
        std::ifstream ifs(inF, std::ios::binary);
        std::ofstream ofs(outF, std::ios::binary);
        if (!ifs) { std::cerr << "Cannot open input file: " << inF << std::endl; return false; }
        if (!ofs) { std::cerr << "Cannot open output file: " << outF << std::endl; return false; }
        
        std::vector<unsigned char> iv(16);
        ifs.read(reinterpret_cast<char*>(iv.data()), iv.size());
        if (ifs.gcount() != static_cast<std::streamsize>(iv.size())) {
            std::cerr << "Error reading IV from file." << std::endl;
            return false;
        }
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { std::cerr << "Error creating decryption context." << std::endl; return false; }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            std::cerr << "Error initializing decryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        const int bufSize = 4096;
        std::vector<unsigned char> inbuf(bufSize), outbuf(bufSize + AES_BLOCK_SIZE);
        int outLen = 0;
        while (ifs) {
            ifs.read(reinterpret_cast<char*>(inbuf.data()), bufSize);
            int r = ifs.gcount();
            if (r > 0) {
                if (EVP_DecryptUpdate(ctx, outbuf.data(), &outLen, inbuf.data(), r) != 1) {
                    std::cerr << "Decryption update error." << std::endl;
                    EVP_CIPHER_CTX_free(ctx);
                    return false;
                }
                ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
            }
        }
        if (EVP_DecryptFinal_ex(ctx, outbuf.data(), &outLen) != 1) {
            std::cerr << "Decryption finalization error." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        ofs.write(reinterpret_cast<const char*>(outbuf.data()), outLen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    // Sign a file using RSA private key (SHA-256)
bool signFile(const std::string &inF, const std::string &sigFile, const std::string &privKeyFile) {
    std::ifstream ifs(inF, std::ios::binary);
    if (!ifs) {
        std::cerr << "Cannot open input file for signing: " << inF << std::endl;
        return false;
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(ifs)), {});
    ifs.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    FILE *fp = fopen(privKeyFile.c_str(), "rb");
    if (!fp) { std::cerr << "Cannot open private key file: " << privKeyFile << std::endl; return false; }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!rsa) { std::cerr << "Invalid private key." << std::endl; return false; }

    unsigned int sigLen = RSA_size(rsa);
    std::vector<unsigned char> signature(sigLen);
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &sigLen, rsa) != 1) {
        std::cerr << "RSA_sign failed." << std::endl;
        RSA_free(rsa);
        return false;
    }
    RSA_free(rsa);
    signature.resize(sigLen);

    std::ofstream ofs(sigFile, std::ios::binary);
    if (!ofs) { std::cerr << "Cannot open signature file: " << sigFile << std::endl; return false; }
    ofs.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    ofs.close();

    std::cout << "Signature created successfully and saved to " << sigFile << std::endl; // Print success message
    return true;
}

// Verify signature using RSA public key (SHA-256)
bool verifySignature(const std::string &inF, const std::string &sigFile, const std::string &pubKeyFile) {
    std::ifstream ifs(inF, std::ios::binary);
    if (!ifs) {
        std::cerr << "Cannot open input file for verification: " << inF << std::endl;
        return false;
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(ifs)), {});
    ifs.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);

    std::ifstream sigifs(sigFile, std::ios::binary);
    if (!sigifs) { std::cerr << "Cannot open signature file: " << sigFile << std::endl; return false; }
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sigifs)), {});
    sigifs.close();

    FILE *fp = fopen(pubKeyFile.c_str(), "rb");
    if (!fp) { std::cerr << "Cannot open public key file: " << pubKeyFile << std::endl; return false; }
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!rsa) { std::cerr << "Invalid public key." << std::endl; return false; }

    bool result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                             signature.data(), signature.size(), rsa) == 1;
    RSA_free(rsa);

    if (result) {
        std::cout << "Signature verified successfully." << std::endl; // Print success message
    } else {
        std::cout << "Signature verification failed." << std::endl; // Print failure message
    }
    return result;
}

};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  --generate-keys\n"
                  << "  --encrypt <input_file> <encrypted_file> <encrypted_key_file> <recipient_pub.pem>\n"
                  << "  --decrypt <encrypted_file> <decrypted_file> <encrypted_key_file> <recipient_priv.pem>\n"
                  << "  --encrypt-sign <input_file> <encrypted_file> <encrypted_key_file> <recipient_pub.pem> <sender_priv.pem> <signature.sig>\n"
                  << "  --decrypt-verify <encrypted_file> <decrypted_file> <encrypted_key_file> <recipient_priv.pem> <sender_pub.pem> <signature.sig>\n";
        return 1;
    }

    std::string mode = argv[1];
    HybridEnc he;

    if (mode == "--generate-keys") {
        if (!he.genRSA("sender_priv.pem", "sender_pub.pem")) {
            std::cerr << "Failed to generate sender keys.\n";
            return 1;
        }
        if (!he.genRSA("recipient_priv.pem", "recipient_pub.pem")) {
            std::cerr << "Failed to generate recipient keys.\n";
            return 1;
        }
        std::cout << "RSA key pairs generated.\n";
    }
    else if (mode == "--encrypt") {
        if (argc < 6) { std::cerr << "Insufficient arguments for encryption.\n"; return 1; }
        std::string inF = argv[2], encFile = argv[3], encKeyFile = argv[4], pubFile = argv[5];
        auto aesKey = he.genAESKey(); if(aesKey.empty()) { std::cerr << "AES key generation failed.\n"; return 1; }
        auto iv = he.genIV(); if(iv.empty()) { std::cerr << "IV generation failed.\n"; return 1; }
        if (!he.aesEncFile(inF, encFile, aesKey, iv)) { std::cerr << "AES file encryption failed.\n"; return 1; }
        auto encKey = he.encAESKey(aesKey, pubFile); if(encKey.empty()) { std::cerr << "AES key encryption failed.\n"; return 1; }
        std::ofstream ofs(encKeyFile, std::ios::binary); if (!ofs) { std::cerr << "Failed to open file for writing encrypted key.\n"; return 1; }
        ofs.write(reinterpret_cast<const char*>(encKey.data()), encKey.size()); ofs.close();
        std::cout << "File encrypted successfully.\n";
    }
    else if (mode == "--decrypt") {
        if (argc < 6) { std::cerr << "Insufficient arguments for decryption.\n"; return 1; }
        std::string encFile = argv[2], outF = argv[3], encKeyFile = argv[4], privFile = argv[5];
        std::ifstream ifs(encKeyFile, std::ios::binary); if (!ifs) { std::cerr << "Failed to open encrypted key file.\n"; return 1; }
        std::vector<unsigned char> encKey((std::istreambuf_iterator<char>(ifs)), {}); ifs.close();
        auto aesKey = he.decAESKey(encKey, privFile); if(aesKey.empty()) { std::cerr << "Failed to decrypt AES key.\n"; return 1; }
        if (!he.aesDecFile(encFile, outF, aesKey)) { std::cerr << "AES file decryption failed.\n"; return 1; }
        std::cout << "File decrypted successfully.\n";
    }
    else if (mode == "--encrypt-sign") {
        if (argc < 8) { std::cerr << "Insufficient arguments for encrypt-sign.\n"; return 1; }
        std::string inF = argv[2], encFile = argv[3], encKeyFile = argv[4], pubFile = argv[5];
        std::string privKeyFile = argv[6], sigFile = argv[7];
        // Encrypt
        auto aesKey = he.genAESKey(); if(aesKey.empty()) { std::cerr << "AES key gen failed.\n"; return 1; }
        auto iv = he.genIV(); if(iv.empty()) { std::cerr << "IV gen failed.\n"; return 1; }
        if (!he.aesEncFile(inF, encFile, aesKey, iv)) { std::cerr << "AES encryption failed.\n"; return 1; }
        auto encKey = he.encAESKey(aesKey, pubFile); if(encKey.empty()) { std::cerr << "Key encryption failed.\n"; return 1; }
        std::ofstream ofs(encKeyFile, std::ios::binary); ofs.write(reinterpret_cast<const char*>(encKey.data()), encKey.size()); ofs.close();
        // Sign encrypted file
        if (!he.signFile(encFile, sigFile, privKeyFile)) { std::cerr << "File signing failed.\n"; return 1; }
        std::cout << "File encrypted and signed successfully.\n";
    }
    else if (mode == "--decrypt-verify") {
        if (argc < 8) { std::cerr << "Insufficient arguments for decrypt-verify.\n"; return 1; }
        std::string encFile = argv[2], outF = argv[3], encKeyFile = argv[4], privFile = argv[5];
        std::string pubKeyFile = argv[6], sigFile = argv[7];
        // Verify signature
        if (!he.verifySignature(encFile, sigFile, pubKeyFile)) {
            std::cerr << "Signature verification failed.\n";
            return 1;
        }
        std::cout << "Signature verified. Proceeding to decryption.\n";
        // Decrypt
        std::ifstream ifs(encKeyFile, std::ios::binary); std::vector<unsigned char> encKey((std::istreambuf_iterator<char>(ifs)), {}); ifs.close();
        auto aesKey = he.decAESKey(encKey, privFile); if(aesKey.empty()) { std::cerr << "AES key decryption failed.\n"; return 1; }
        if (!he.aesDecFile(encFile, outF, aesKey)) { std::cerr << "File decryption failed.\n"; return 1; }
        std::cout << "File verified and decrypted successfully.\n";
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    return 0;
}
