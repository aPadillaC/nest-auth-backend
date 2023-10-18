import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';

import { CreateUserDto, UpdateUserDto, LoginDto, RegisterUserDto } from './dto';

import { User } from './entities/user.entity';


import * as bcryptjs from 'bcryptjs'

import { JwtPayload } from './interface/jwt-payload';
import { LoginResponse } from './interface/login-response';


@Injectable()
export class AuthService {

  constructor( 
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}




  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      
      // Desestructuramos el password y el resto del objeto lo guardamos en la variable llamada "userData"
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({

        password: bcryptjs.hashSync( password, 10),
        ...userData
      });

      await newUser.save();

      const { password:_ , ...user } = newUser.toJSON();

      return user;

    } catch (error) {

      if( error.code === 11000) {

        throw new BadRequestException( `${ createUserDto.email } already exists!`)
      }

      throw new InternalServerErrorException( `Something terrible happen!!!`)
      
    }

  }




  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create( registerUserDto );

    return {

      user: user,
      token: this.getJwtToken( {id: user._id })
    }
  }




  async login( loginUserDto: LoginDto ): Promise<LoginResponse> {

    const { email, password } = loginUserDto;

    const user = await this.userModel.findOne( {email} );

    if( !user ) {

      throw new UnauthorizedException(`Not valid credentials - email`);
    }


    if ( !bcryptjs.compareSync( password, user.password)) {

      throw new UnauthorizedException(`Not valid credentials - password`);
    }

    const { password:_ , ...rest } = user.toJSON();

      return {
        user: rest,
        token: this.getJwtToken( {id: user.id }),
      };

  }




  findAll(): Promise<User[]> {
    return this.userModel.find();
  }


  
  async findUserByid( id: string ){

    const user = await this.userModel.findById( id );

    // Usamos toJSON() para asegurarnos que no nos mete funciones o metodos dentro de la variable
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  

  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateUserDto: UpdateUserDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }


  getJwtToken( payload: JwtPayload) {

    const token = this.jwtService.sign(payload);
    return token;
  }
}
