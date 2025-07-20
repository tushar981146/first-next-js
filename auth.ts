import NextAuth from 'next-auth'
import { authConfig } from './auth.config'
import Credentials from 'next-auth/providers/credentials'
import { z } from 'zod'
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';


const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });


async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User[]>`SELECT * FROM users WHERE email = ${email}`;
        return user[0];
    } catch (error) {
        console.error('Error fetching user:', error);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [
        Credentials({
            async authorize(credentials) {
                console.log('credentials', credentials)
                const parsedCredentials = z
                    .object({ email: z.string().email(), password: z.string().min(6) })
                    .safeParse(credentials);

                if (parsedCredentials.success) {
                    const { email, password } = parsedCredentials.data;
                    console.log(`email: ${email}, password: ${password}`);
                    const user = await getUser(email);
                    console.log('User:', user)
                    if (!user) return null;
                    const PasswordMatch = await bcrypt.compare(password, user.password);
                    if (PasswordMatch) return user;
                }

                 console.log('Invalid credentials');
                return null;
            },
        }),
    ]
})

